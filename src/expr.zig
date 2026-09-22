const std = @import("std");
const rowmod = @import("row.zig");
const idx = @import("index.zig");
const querymod = @import("query.zig");
const dbmod = @import("db.zig");

const Allocator = std.mem.Allocator;
const Predicate = querymod.Predicate;
const Condition = querymod.Condition;

pub const ParseError = error{
    UnexpectedToken,
    UnexpectedEnd,
    InvalidIdentifier,
    UnknownOperator,
    InvalidValue,
} || Allocator.Error;

pub const Parsed = struct {
    arena: std.heap.ArenaAllocator,
    predicate: Predicate,

    pub fn deinit(self: *Parsed) void {
        self.arena.deinit();
    }
};

const TokenKind = enum { lparen, rparen, word, eof };

const Token = struct {
    kind: TokenKind,
    text: []const u8,
};

const Lexer = struct {
    src: []const u8,
    pos: usize = 0,

    fn next(self: *Lexer) Token {
        while (self.pos < self.src.len and std.ascii.isWhitespace(self.src[self.pos])) : (self.pos += 1) {}
        if (self.pos >= self.src.len) return .{ .kind = .eof, .text = "" };

        const c = self.src[self.pos];
        if (c == '(') {
            self.pos += 1;
            return .{ .kind = .lparen, .text = "(" };
        }
        if (c == ')') {
            self.pos += 1;
            return .{ .kind = .rparen, .text = ")" };
        }

        const start = self.pos;
        while (self.pos < self.src.len) {
            const ch = self.src[self.pos];
            if (std.ascii.isWhitespace(ch) or ch == '(' or ch == ')') break;
            self.pos += 1;
        }
        return .{ .kind = .word, .text = self.src[start..self.pos] };
    }
};

fn isKeyword(tok: Token, kw: []const u8) bool {
    return tok.kind == .word and std.mem.eql(u8, tok.text, kw);
}

const Parser = struct {
    lexer: Lexer,
    allocator: Allocator,
    cur: Token,

    fn advance(self: *Parser) void {
        self.cur = self.lexer.next();
    }

    fn parseOr(self: *Parser) ParseError!Predicate {
        var list = std.ArrayList(Predicate).init(self.allocator);
        try list.append(try self.parseAnd());
        while (isKeyword(self.cur, "or")) {
            self.advance();
            try list.append(try self.parseAnd());
        }
        if (list.items.len == 1) return list.items[0];
        return .{ .or_ = try list.toOwnedSlice() };
    }

    fn parseAnd(self: *Parser) ParseError!Predicate {
        var list = std.ArrayList(Predicate).init(self.allocator);
        try list.append(try self.parseUnary());
        while (isKeyword(self.cur, "and")) {
            self.advance();
            try list.append(try self.parseUnary());
        }
        if (list.items.len == 1) return list.items[0];
        return .{ .and_ = try list.toOwnedSlice() };
    }

    fn parseUnary(self: *Parser) ParseError!Predicate {
        if (isKeyword(self.cur, "not")) {
            self.advance();
            const inner = try self.parseUnary();
            const boxed = try self.allocator.create(Predicate);
            boxed.* = inner;
            return .{ .not_ = boxed };
        }
        return self.parsePrimary();
    }

    fn parsePrimary(self: *Parser) ParseError!Predicate {
        if (self.cur.kind == .lparen) {
            self.advance();
            const inner = try self.parseOr();
            if (self.cur.kind != .rparen) return error.UnexpectedToken;
            self.advance();
            return inner;
        }
        return self.parseCondition();
    }

    fn parseCondition(self: *Parser) ParseError!Predicate {
        if (self.cur.kind != .word) return if (self.cur.kind == .eof) error.UnexpectedEnd else error.UnexpectedToken;
        const field = self.cur.text;
        if (!idx.validIdentifier(field)) return error.InvalidIdentifier;
        const fieldCopy = try self.allocator.dupe(u8, field);
        self.advance();

        if (self.cur.kind != .word) return error.UnexpectedEnd;
        const op = self.cur.text;
        self.advance();

        if (std.mem.eql(u8, op, "in")) return self.parseIn(fieldCopy);
        if (std.mem.eql(u8, op, "between")) return self.parseBetween(fieldCopy);
        if (std.mem.eql(u8, op, "is_null")) return .{ .is_null = fieldCopy };
        if (std.mem.eql(u8, op, "is_not_null")) return .{ .is_not_null = fieldCopy };

        if (self.cur.kind != .word) return error.UnexpectedEnd;
        const rawValue = rowmod.Value.parseCli(self.cur.text) catch return error.InvalidValue;
        const value = try rawValue.dupe(self.allocator);
        self.advance();

        const cond = Condition{ .field = fieldCopy, .value = value };
        if (std.mem.eql(u8, op, "eq")) return .{ .eq = cond };
        if (std.mem.eql(u8, op, "ne")) return .{ .ne = cond };
        if (std.mem.eql(u8, op, "lt")) return .{ .lt = cond };
        if (std.mem.eql(u8, op, "lte")) return .{ .lte = cond };
        if (std.mem.eql(u8, op, "gt")) return .{ .gt = cond };
        if (std.mem.eql(u8, op, "gte")) return .{ .gte = cond };
        if (std.mem.eql(u8, op, "like")) {
            if (value != .text) return error.InvalidValue;
            return .{ .like = cond };
        }
        return error.UnknownOperator;
    }

    fn parseIn(self: *Parser, field: []const u8) ParseError!Predicate {
        if (self.cur.kind != .lparen) return if (self.cur.kind == .eof) error.UnexpectedEnd else error.UnexpectedToken;
        self.advance();

        var list = std.ArrayList(Predicate).init(self.allocator);
        while (self.cur.kind != .rparen) {
            if (self.cur.kind != .word) return if (self.cur.kind == .eof) error.UnexpectedEnd else error.UnexpectedToken;
            const rawValue = rowmod.Value.parseCli(self.cur.text) catch return error.InvalidValue;
            const value = try rawValue.dupe(self.allocator);
            self.advance();
            try list.append(.{ .eq = .{ .field = field, .value = value } });
        }
        self.advance();

        if (list.items.len == 1) return list.items[0];
        return .{ .or_ = try list.toOwnedSlice() };
    }

    fn parseBetween(self: *Parser, field: []const u8) ParseError!Predicate {
        if (self.cur.kind != .word) return error.UnexpectedEnd;
        const rawLow = rowmod.Value.parseCli(self.cur.text) catch return error.InvalidValue;
        const low = try rawLow.dupe(self.allocator);
        self.advance();

        if (!isKeyword(self.cur, "and")) return if (self.cur.kind == .eof) error.UnexpectedEnd else error.UnexpectedToken;
        self.advance();

        if (self.cur.kind != .word) return error.UnexpectedEnd;
        const rawHigh = rowmod.Value.parseCli(self.cur.text) catch return error.InvalidValue;
        const high = try rawHigh.dupe(self.allocator);
        self.advance();

        const bounds = try self.allocator.alloc(Predicate, 2);
        bounds[0] = .{ .gte = .{ .field = field, .value = low } };
        bounds[1] = .{ .lte = .{ .field = field, .value = high } };
        return .{ .and_ = bounds };
    }
};

pub fn parse(backing: Allocator, text: []const u8) ParseError!Parsed {
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const allocator = arena.allocator();

    var p = Parser{ .lexer = .{ .src = text }, .allocator = allocator, .cur = undefined };
    p.cur = p.lexer.next();

    const pred = try p.parseOr();
    if (p.cur.kind != .eof) return error.UnexpectedToken;

    return .{ .arena = arena, .predicate = pred };
}

fn evalStr(allocator: Allocator, text: []const u8, row: *const rowmod.Row) !bool {
    var parsed = try parse(allocator, text);
    defer parsed.deinit();
    return parsed.predicate.evaluate(row);
}

test "parses a single condition" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("city", .{ .text = "warsaw" });

    try std.testing.expect(try evalStr(allocator, "city eq s:warsaw", &row));
    try std.testing.expect(!try evalStr(allocator, "city eq s:krakow", &row));
}

test "and binds tighter than or" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("a", .{ .int = 1 });
    try row.set("b", .{ .int = 2 });
    try row.set("c", .{ .int = 99 });

    try std.testing.expect(try evalStr(allocator, "a eq i:1 or b eq i:2 and c eq i:3", &row));

    var row2 = rowmod.Row.init(allocator);
    defer row2.deinit();
    try row2.set("a", .{ .int = 0 });
    try row2.set("b", .{ .int = 2 });
    try row2.set("c", .{ .int = 99 });
    try std.testing.expect(!try evalStr(allocator, "a eq i:1 or b eq i:2 and c eq i:3", &row2));
}

test "parentheses override default precedence" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("a", .{ .int = 0 });
    try row.set("b", .{ .int = 2 });
    try row.set("c", .{ .int = 5 });

    try std.testing.expect(try evalStr(allocator, "(a eq i:1 or b eq i:2) and c eq i:5", &row));
    try std.testing.expect(!try evalStr(allocator, "(a eq i:1 or b eq i:2) and c eq i:6", &row));
}

test "not negates the following term" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("age", .{ .int = 20 });

    try std.testing.expect(try evalStr(allocator, "not age eq i:10", &row));
    try std.testing.expect(!try evalStr(allocator, "not age eq i:20", &row));
    try std.testing.expect(!try evalStr(allocator, "not (age eq i:10 or age eq i:20)", &row));
}

test "nested parentheses and multiple not" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("x", .{ .int = 5 });

    try std.testing.expect(try evalStr(allocator, "not not x eq i:5", &row));
    try std.testing.expect(try evalStr(allocator, "((x eq i:5))", &row));
}

test "range and inequality operators parse and evaluate" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("score", .{ .int = 42 });

    try std.testing.expect(try evalStr(allocator, "score gt i:10", &row));
    try std.testing.expect(try evalStr(allocator, "score gte i:42", &row));
    try std.testing.expect(try evalStr(allocator, "score lt i:100", &row));
    try std.testing.expect(try evalStr(allocator, "score lte i:42", &row));
    try std.testing.expect(try evalStr(allocator, "score ne i:0", &row));
}

test "like matches SQL-style wildcards and rejects non-text patterns" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("name", .{ .text = "Ada Lovelace" });
    try row.set("age", .{ .int = 36 });

    try std.testing.expect(try evalStr(allocator, "name like s:Ada%", &row));
    try std.testing.expect(try evalStr(allocator, "name like s:%Lovelace", &row));
    try std.testing.expect(try evalStr(allocator, "name like s:%Love%", &row));
    try std.testing.expect(!try evalStr(allocator, "name like s:Boris%", &row));
    try std.testing.expect(!try evalStr(allocator, "age like s:3%", &row));
    try std.testing.expect(try evalStr(allocator, "name like s:Ada% and age eq i:36", &row));
    try std.testing.expect(!try evalStr(allocator, "not name like s:Ada%", &row));

    try std.testing.expectError(error.InvalidValue, parse(allocator, "name like i:5"));
}

test "is_null matches a row missing the field, is_not_null matches a row that has it" {
    const allocator = std.testing.allocator;
    var withCity = rowmod.Row.init(allocator);
    defer withCity.deinit();
    try withCity.set("city", .{ .text = "warsaw" });

    var withoutCity = rowmod.Row.init(allocator);
    defer withoutCity.deinit();
    try withoutCity.set("age", .{ .int = 30 });

    try std.testing.expect(!try evalStr(allocator, "city is_null", &withCity));
    try std.testing.expect(try evalStr(allocator, "city is_not_null", &withCity));
    try std.testing.expect(try evalStr(allocator, "city is_null", &withoutCity));
    try std.testing.expect(!try evalStr(allocator, "city is_not_null", &withoutCity));
}

test "is_null treats an explicit Value.none the same as a missing field" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("nickname", .{ .none = {} });

    try std.testing.expect(try evalStr(allocator, "nickname is_null", &row));
    try std.testing.expect(!try evalStr(allocator, "nickname is_not_null", &row));
}

test "is_null and is_not_null take no trailing value and combine with and/or/not" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("age", .{ .int = 30 });

    try std.testing.expect(try evalStr(allocator, "city is_null and age eq i:30", &row));
    try std.testing.expect(!try evalStr(allocator, "city is_not_null or age eq i:99", &row));
    try std.testing.expect(try evalStr(allocator, "not city is_not_null", &row));

    var parsed = try parse(allocator, "city is_null");
    defer parsed.deinit();
    try std.testing.expect(parsed.predicate == .is_null);
    try std.testing.expectEqualStrings("city", parsed.predicate.is_null);
}

test "field name copy and value copy outlive the source text" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("name", .{ .text = "ada" });

    var buf: [64]u8 = undefined;
    const src = try std.fmt.bufPrint(&buf, "name eq s:ada", .{});
    var parsed = try parse(allocator, src);
    @memset(&buf, 'X');
    try std.testing.expect(parsed.predicate.evaluate(&row));
    parsed.deinit();
}

test "rejects malformed expressions" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UnexpectedEnd, parse(allocator, "age eq"));
    try std.testing.expectError(error.UnexpectedEnd, parse(allocator, "age"));
    try std.testing.expectError(error.UnknownOperator, parse(allocator, "age foo i:1"));
    try std.testing.expectError(error.InvalidValue, parse(allocator, "age eq i:notanumber"));
    try std.testing.expectError(error.UnexpectedToken, parse(allocator, "(age eq i:1"));
    try std.testing.expectError(error.UnexpectedToken, parse(allocator, "age eq i:1)"));
    try std.testing.expectError(error.UnexpectedEnd, parse(allocator, ""));
    try std.testing.expectError(error.UnexpectedToken, parse(allocator, "age eq i:1 age eq i:2"));
}

test "in matches any value in the list" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("city", .{ .text = "krakow" });

    try std.testing.expect(try evalStr(allocator, "city in (s:warsaw s:krakow s:gdansk)", &row));
    try std.testing.expect(!try evalStr(allocator, "city in (s:warsaw s:gdansk)", &row));
    try std.testing.expect(!try evalStr(allocator, "city in ()", &row));
    try std.testing.expect(try evalStr(allocator, "city in (s:krakow) and not city eq s:warsaw", &row));
    try std.testing.expect(!try evalStr(allocator, "not city in (s:warsaw s:krakow)", &row));
}

test "in with a single value collapses to a bare eq leaf" {
    const allocator = std.testing.allocator;
    var parsed = try parse(allocator, "city in (s:warsaw)");
    defer parsed.deinit();
    try std.testing.expect(parsed.predicate == .eq);
    try std.testing.expectEqualStrings("city", parsed.predicate.eq.field);
}

test "between is inclusive on both ends" {
    const allocator = std.testing.allocator;
    var row = rowmod.Row.init(allocator);
    defer row.deinit();
    try row.set("age", .{ .int = 30 });

    try std.testing.expect(try evalStr(allocator, "age between i:30 and i:40", &row));
    try std.testing.expect(try evalStr(allocator, "age between i:20 and i:30", &row));
    try std.testing.expect(!try evalStr(allocator, "age between i:31 and i:40", &row));
    try std.testing.expect(!try evalStr(allocator, "age between i:10 and i:29", &row));
    try std.testing.expect(try evalStr(allocator, "age between i:25 and i:35 and age ne i:0", &row));
    try std.testing.expect(!try evalStr(allocator, "not age between i:25 and i:35", &row));
}

test "between desugars to a two-leaf and_ of gte/lte" {
    const allocator = std.testing.allocator;
    var parsed = try parse(allocator, "age between i:1 and i:2");
    defer parsed.deinit();
    try std.testing.expect(parsed.predicate == .and_);
    try std.testing.expectEqual(@as(usize, 2), parsed.predicate.and_.len);
    try std.testing.expect(parsed.predicate.and_[0] == .gte);
    try std.testing.expect(parsed.predicate.and_[1] == .lte);
}

test "in and between reject malformed input" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UnexpectedToken, parse(allocator, "city in s:warsaw"));
    try std.testing.expectError(error.UnexpectedEnd, parse(allocator, "city in (s:warsaw"));
    try std.testing.expectError(error.InvalidValue, parse(allocator, "age in (i:notanumber)"));
    try std.testing.expectError(error.UnexpectedEnd, parse(allocator, "age between i:1"));
    try std.testing.expectError(error.UnexpectedToken, parse(allocator, "age between i:1 or i:2"));
    try std.testing.expectError(error.InvalidValue, parse(allocator, "age between i:1 and i:notanumber"));
}

fn openTemp(tmp: *std.testing.TmpDir, allocator: Allocator) !dbmod.Db {
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);
    return dbmod.Db.open(allocator, dbPath, .{});
}

test "a single-value in reaches Table.select through an index like eq does" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try querymod.Table.open(&db, allocator, "cities");
    defer table.deinit();
    try table.createIndex("city");
    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "oslo" } }});
    try table.put(.{ .int = 2 }, &.{.{ .name = "city", .value = .{ .text = "bergen" } }});

    var parsed = try parse(allocator, "city in (s:oslo)");
    defer parsed.deinit();

    var plan = try table.explain(allocator, parsed.predicate);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.index_eq, plan.kind);
    try std.testing.expectEqualStrings("city", plan.indexName.?);

    const results = try table.select(parsed.predicate);
    defer querymod.freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(@as(i64, 1), results[0].get(querymod.pkField).?.int);
}

test "a multi-value in falls back to a full scan and still matches every listed value" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try querymod.Table.open(&db, allocator, "cities");
    defer table.deinit();
    try table.createIndex("city");
    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "oslo" } }});
    try table.put(.{ .int = 2 }, &.{.{ .name = "city", .value = .{ .text = "bergen" } }});
    try table.put(.{ .int = 3 }, &.{.{ .name = "city", .value = .{ .text = "trondheim" } }});

    var parsed = try parse(allocator, "city in (s:oslo s:trondheim)");
    defer parsed.deinit();

    var plan = try table.explain(allocator, parsed.predicate);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.full_scan, plan.kind);

    const results = try table.select(parsed.predicate);
    defer querymod.freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 2), results.len);
}

test "between reaches Table.select through an index range like gte/lte does" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try querymod.Table.open(&db, allocator, "people");
    defer table.deinit();
    try table.createIndex("age");
    var i: i64 = 0;
    while (i < 10) : (i += 1) {
        try table.put(.{ .int = i }, &.{.{ .name = "age", .value = .{ .int = i * 10 } }});
    }

    var parsed = try parse(allocator, "age between i:20 and i:50");
    defer parsed.deinit();

    var plan = try table.explain(allocator, parsed.predicate);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.index_range, plan.kind);
    try std.testing.expectEqualStrings("age", plan.indexName.?);

    const results = try table.select(parsed.predicate);
    defer querymod.freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 4), results.len);
}
