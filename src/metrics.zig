const std = @import("std");
const stats_mod = @import("stats.zig");

// Metrics primitives (counter/gauge/histogram), two independent rate-limiter
// algorithms (token bucket, sliding window counter), and a text-exposition
// registry. Fully additive module: does not touch Db/txn/storage internals,
// only depends on stats.zig's public Stats type for the export helper.

pub const MetricCounter = struct {
    value: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn incr(self: *MetricCounter) void {
        self.incrBy(1);
    }

    pub fn incrBy(self: *MetricCounter, delta: u64) void {
        _ = self.value.fetchAdd(delta, .monotonic);
    }

    pub fn get(self: *const MetricCounter) u64 {
        return self.value.load(.monotonic);
    }

    pub fn reset(self: *MetricCounter) void {
        self.value.store(0, .monotonic);
    }
};

pub const Gauge = struct {
    bits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn set(self: *Gauge, v: f64) void {
        self.bits.store(@bitCast(v), .monotonic);
    }

    pub fn get(self: *const Gauge) f64 {
        const raw = self.bits.load(.monotonic);
        return @bitCast(raw);
    }

    pub fn add(self: *Gauge, delta: f64) void {
        while (true) {
            const cur = self.bits.load(.monotonic);
            const curF: f64 = @bitCast(cur);
            const newBits: u64 = @bitCast(curF + delta);
            if (self.bits.cmpxchgWeak(cur, newBits, .monotonic, .monotonic) == null) return;
        }
    }
};

pub const HistogramError = error{EmptyBounds};

/// Fixed-bucket histogram with Prometheus-style cumulative-bucket quantile
/// estimation. `bounds` must be strictly increasing and is borrowed (caller
/// keeps it alive for the histogram's lifetime); values greater than the
/// last bound land in an implicit +Inf bucket.
pub const Histogram = struct {
    bounds: []const f64,
    counts: []u64,
    sum: f64 = 0,
    total: u64 = 0,
    mutex: std.Thread.Mutex = .{},
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, bounds: []const f64) !Histogram {
        if (bounds.len == 0) return HistogramError.EmptyBounds;
        var i: usize = 1;
        while (i < bounds.len) : (i += 1) {
            std.debug.assert(bounds[i] > bounds[i - 1]);
        }
        const counts = try allocator.alloc(u64, bounds.len + 1);
        @memset(counts, 0);
        return .{ .bounds = bounds, .counts = counts, .allocator = allocator };
    }

    pub fn deinit(self: *Histogram) void {
        self.allocator.free(self.counts);
        self.* = undefined;
    }

    pub fn observe(self: *Histogram, value: f64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var idx: usize = self.bounds.len;
        for (self.bounds, 0..) |bound, i| {
            if (value <= bound) {
                idx = i;
                break;
            }
        }
        self.counts[idx] += 1;
        self.sum += value;
        self.total += 1;
    }

    pub fn count(self: *const Histogram) u64 {
        return self.total;
    }

    pub fn mean(self: *const Histogram) f64 {
        if (self.total == 0) return 0;
        return self.sum / @as(f64, @floatFromInt(self.total));
    }

    /// Linear-interpolation quantile estimate over cumulative bucket counts,
    /// same algorithm Prometheus uses for `histogram_quantile`. q in [0, 1].
    pub fn quantile(self: *Histogram, q: f64) f64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.total == 0 or self.bounds.len == 0) return 0;
        const clamped = std.math.clamp(q, 0, 1);
        const target = clamped * @as(f64, @floatFromInt(self.total));

        var cumulative: u64 = 0;
        var i: usize = 0;
        while (i < self.counts.len) : (i += 1) {
            const prevCumulative = cumulative;
            cumulative += self.counts[i];
            if (@as(f64, @floatFromInt(cumulative)) >= target) {
                if (i == 0) return self.bounds[0];
                if (i == self.bounds.len) return self.bounds[self.bounds.len - 1];
                const lower = self.bounds[i - 1];
                const upper = self.bounds[i];
                const countInBucket = cumulative - prevCumulative;
                if (countInBucket == 0) return upper;
                const fraction = (target - @as(f64, @floatFromInt(prevCumulative))) / @as(f64, @floatFromInt(countInBucket));
                return lower + fraction * (upper - lower);
            }
        }
        return self.bounds[self.bounds.len - 1];
    }

    pub fn bucketCount(self: *Histogram, idx: usize) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.counts[idx];
    }
};

pub fn linearBuckets(allocator: std.mem.Allocator, start: f64, width: f64, n: usize) ![]f64 {
    std.debug.assert(n > 0);
    std.debug.assert(width > 0);
    const out = try allocator.alloc(f64, n);
    var i: usize = 0;
    while (i < n) : (i += 1) out[i] = start + width * @as(f64, @floatFromInt(i));
    return out;
}

pub fn exponentialBuckets(allocator: std.mem.Allocator, start: f64, factor: f64, n: usize) ![]f64 {
    std.debug.assert(n > 0);
    std.debug.assert(start > 0);
    std.debug.assert(factor > 1);
    const out = try allocator.alloc(f64, n);
    var cur = start;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        out[i] = cur;
        cur *= factor;
    }
    return out;
}

/// Classic token-bucket rate limiter. Time is passed in explicitly as
/// nanoseconds so the algorithm is deterministic and testable; `tryAcquireNow`
/// wraps it with the wall clock for real use.
pub const TokenBucket = struct {
    capacity: f64,
    refillPerSecond: f64,
    tokens: f64,
    lastRefillNanos: u64,
    mutex: std.Thread.Mutex = .{},

    pub fn init(capacity: f64, refillPerSecond: f64, nowNanos: u64) TokenBucket {
        std.debug.assert(capacity > 0);
        std.debug.assert(refillPerSecond > 0);
        return .{
            .capacity = capacity,
            .refillPerSecond = refillPerSecond,
            .tokens = capacity,
            .lastRefillNanos = nowNanos,
        };
    }

    fn refillLocked(self: *TokenBucket, nowNanos: u64) void {
        if (nowNanos <= self.lastRefillNanos) return;
        const elapsedNanos = nowNanos - self.lastRefillNanos;
        const elapsedSeconds = @as(f64, @floatFromInt(elapsedNanos)) / std.time.ns_per_s;
        self.tokens = @min(self.capacity, self.tokens + elapsedSeconds * self.refillPerSecond);
        self.lastRefillNanos = nowNanos;
    }

    /// Attempts to consume `n` tokens at time `nowNanos`. All-or-nothing:
    /// never partially consumes on failure.
    pub fn tryAcquireAt(self: *TokenBucket, n: f64, nowNanos: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.refillLocked(nowNanos);
        if (self.tokens >= n) {
            self.tokens -= n;
            return true;
        }
        return false;
    }

    pub fn tryAcquireNow(self: *TokenBucket, n: f64) bool {
        return self.tryAcquireAt(n, @intCast(std.time.nanoTimestamp()));
    }

    pub fn availableAt(self: *TokenBucket, nowNanos: u64) f64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.refillLocked(nowNanos);
        return self.tokens;
    }
};

/// Sliding-window-counter rate limiter (the "Cloudflare" approximation):
/// tracks a count for the current fixed window and the previous one, and
/// weights the previous window's count by how much of it still overlaps the
/// trailing `windowNanos` interval. O(1) memory unlike a sliding log, more
/// accurate at window boundaries than a plain fixed window.
pub const SlidingWindowLimiter = struct {
    limit: u64,
    windowNanos: u64,
    currentWindowStart: u64,
    currentCount: u64 = 0,
    previousCount: u64 = 0,
    mutex: std.Thread.Mutex = .{},

    pub fn init(limit: u64, windowNanos: u64, nowNanos: u64) SlidingWindowLimiter {
        std.debug.assert(limit > 0);
        std.debug.assert(windowNanos > 0);
        return .{
            .limit = limit,
            .windowNanos = windowNanos,
            .currentWindowStart = alignedWindowStart(nowNanos, windowNanos),
        };
    }

    fn alignedWindowStart(nowNanos: u64, windowNanos: u64) u64 {
        return (nowNanos / windowNanos) * windowNanos;
    }

    fn rotateLocked(self: *SlidingWindowLimiter, nowNanos: u64) void {
        const windowStart = alignedWindowStart(nowNanos, self.windowNanos);
        if (windowStart == self.currentWindowStart) return;
        const windowsElapsed = (windowStart - self.currentWindowStart) / self.windowNanos;
        if (windowsElapsed == 1) {
            self.previousCount = self.currentCount;
        } else {
            self.previousCount = 0;
        }
        self.currentCount = 0;
        self.currentWindowStart = windowStart;
    }

    pub fn allowAt(self: *SlidingWindowLimiter, nowNanos: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.rotateLocked(nowNanos);
        const elapsedInWindow = nowNanos - self.currentWindowStart;
        const overlap = 1.0 - @as(f64, @floatFromInt(elapsedInWindow)) / @as(f64, @floatFromInt(self.windowNanos));
        const clampedOverlap = std.math.clamp(overlap, 0, 1);
        const weighted = @as(f64, @floatFromInt(self.previousCount)) * clampedOverlap + @as(f64, @floatFromInt(self.currentCount));
        if (weighted >= @as(f64, @floatFromInt(self.limit))) return false;
        self.currentCount += 1;
        return true;
    }

    pub fn allowNow(self: *SlidingWindowLimiter) bool {
        return self.allowAt(@intCast(std.time.nanoTimestamp()));
    }
};

const MetricKind = enum { counter, gauge, histogram };

const MetricRef = union(MetricKind) {
    counter: *const MetricCounter,
    gauge: *const Gauge,
    histogram: *Histogram,
};

/// Named-metric registry with a Prometheus-style text exporter. Stores only
/// borrowed pointers (owned name copies) - callers keep the metrics alive.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMapUnmanaged(MetricRef) = .{},

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Registry) void {
        var it = self.entries.keyIterator();
        while (it.next()) |key| self.allocator.free(key.*);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    fn put(self: *Registry, name: []const u8, ref: MetricRef) !void {
        if (self.entries.getPtr(name)) |existing| {
            existing.* = ref;
            return;
        }
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        try self.entries.put(self.allocator, owned, ref);
    }

    pub fn registerCounter(self: *Registry, name: []const u8, c: *const MetricCounter) !void {
        try self.put(name, .{ .counter = c });
    }

    pub fn registerGauge(self: *Registry, name: []const u8, g: *const Gauge) !void {
        try self.put(name, .{ .gauge = g });
    }

    pub fn registerHistogram(self: *Registry, name: []const u8, h: *Histogram) !void {
        try self.put(name, .{ .histogram = h });
    }

    pub fn count(self: *const Registry) usize {
        return self.entries.count();
    }

    /// Writes every registered metric in Prometheus exposition format.
    /// Output is sorted by name so it is deterministic (and diffable).
    pub fn exportText(self: *Registry, allocator: std.mem.Allocator, writer: anytype) !void {
        var names = try allocator.alloc([]const u8, self.entries.count());
        defer allocator.free(names);
        var it = self.entries.keyIterator();
        var i: usize = 0;
        while (it.next()) |key| : (i += 1) names[i] = key.*;
        std.mem.sort([]const u8, names, {}, lessThanStr);

        for (names) |name| {
            const ref = self.entries.get(name).?;
            switch (ref) {
                .counter => |c| try writer.print("{s} {d}\n", .{ name, c.get() }),
                .gauge => |g| try writer.print("{s} {d}\n", .{ name, g.get() }),
                .histogram => |h| {
                    var cumulative: u64 = 0;
                    for (h.bounds, 0..) |bound, idx| {
                        cumulative += h.counts[idx];
                        try writer.print("{s}_bucket{{le=\"{d}\"}} {d}\n", .{ name, bound, cumulative });
                    }
                    cumulative += h.counts[h.bounds.len];
                    try writer.print("{s}_bucket{{le=\"+Inf\"}} {d}\n", .{ name, cumulative });
                    try writer.print("{s}_sum {d}\n", .{ name, h.sum });
                    try writer.print("{s}_count {d}\n", .{ name, h.total });
                },
            }
        }
    }
};

fn lessThanStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// Renders a Db Stats snapshot in the same Prometheus text format used by
/// Registry.exportText, so `stats` output and ad-hoc registry metrics can be
/// scraped through one shared shape.
pub fn formatDbStats(writer: anytype, prefix: []const u8, s: stats_mod.Stats) !void {
    try writer.print("{s}_memtable_entries {d}\n", .{ prefix, s.memtableEntries });
    try writer.print("{s}_memtable_bytes {d}\n", .{ prefix, s.memtableBytes });
    try writer.print("{s}_sstable_count {d}\n", .{ prefix, s.sstableCount });
    try writer.print("{s}_live_entries {d}\n", .{ prefix, s.liveEntries });
    try writer.print("{s}_physical_bytes {d}\n", .{ prefix, s.physicalBytes });
    try writer.print("{s}_cache_hits {d}\n", .{ prefix, s.cacheHits });
    try writer.print("{s}_cache_misses {d}\n", .{ prefix, s.cacheMisses });
    try writer.print("{s}_cache_hit_rate {d:.6}\n", .{ prefix, s.cacheHitRate() });
    try writer.print("{s}_next_seq {d}\n", .{ prefix, s.nextSeq });
    const deepest = s.deepestLevel();
    var i: usize = 0;
    while (i <= deepest) : (i += 1) {
        const level = s.levels[i];
        try writer.print("{s}_level_tables{{level=\"{d}\"}} {d}\n", .{ prefix, i, level.tables });
        try writer.print("{s}_level_entries{{level=\"{d}\"}} {d}\n", .{ prefix, i, level.entries });
    }
}

test "counter incr and incrBy accumulate" {
    var c = MetricCounter{};
    c.incr();
    c.incrBy(41);
    try std.testing.expectEqual(@as(u64, 42), c.get());
    c.reset();
    try std.testing.expectEqual(@as(u64, 0), c.get());
}

test "gauge set/add round trip through bit reinterpretation" {
    var g = Gauge{};
    g.set(3.5);
    try std.testing.expectApproxEqAbs(@as(f64, 3.5), g.get(), 1e-12);
    g.add(-1.25);
    try std.testing.expectApproxEqAbs(@as(f64, 2.25), g.get(), 1e-12);
}

test "histogram observe buckets and mean" {
    const bounds = [_]f64{ 10, 50, 100 };
    var h = try Histogram.init(std.testing.allocator, &bounds);
    defer h.deinit();

    h.observe(5);
    h.observe(20);
    h.observe(20);
    h.observe(75);
    h.observe(1000);

    try std.testing.expectEqual(@as(u64, 1), h.bucketCount(0));
    try std.testing.expectEqual(@as(u64, 2), h.bucketCount(1));
    try std.testing.expectEqual(@as(u64, 1), h.bucketCount(2));
    try std.testing.expectEqual(@as(u64, 1), h.bucketCount(3));
    try std.testing.expectEqual(@as(u64, 5), h.count());
    try std.testing.expectApproxEqAbs(@as(f64, (5 + 20 + 20 + 75 + 1000) / 5.0), h.mean(), 1e-9);
}

test "histogram quantile interpolates within a bucket" {
    const bounds = [_]f64{ 100, 200 };
    var h = try Histogram.init(std.testing.allocator, &bounds);
    defer h.deinit();

    // 4 values land in the (0,100] bucket, evenly spread by construction;
    // linear interpolation only sees prev/cur cumulative counts, so the
    // median of an all-in-one-bucket histogram is the bucket's own bound.
    var i: usize = 0;
    while (i < 4) : (i += 1) h.observe(50);
    try std.testing.expectApproxEqAbs(@as(f64, 100), h.quantile(0.5), 1e-9);

    // Now spread evenly across both finite buckets: p50 should land exactly
    // on the boundary between them.
    h.observe(150);
    h.observe(150);
    h.observe(150);
    h.observe(150);
    // counts: bucket0=4 (<=100), bucket1=4 (<=200) => cumulative [4,8], total 8
    const q50 = h.quantile(0.5);
    try std.testing.expectApproxEqAbs(@as(f64, 100), q50, 1e-9);
}

test "histogram quantile falls back to last bound for the +Inf bucket" {
    const bounds = [_]f64{ 10, 20 };
    var h = try Histogram.init(std.testing.allocator, &bounds);
    defer h.deinit();
    h.observe(5);
    h.observe(9999);
    try std.testing.expectApproxEqAbs(@as(f64, 20), h.quantile(1.0), 1e-9);
}

test "linearBuckets and exponentialBuckets produce expected boundaries" {
    const lin = try linearBuckets(std.testing.allocator, 0, 10, 5);
    defer std.testing.allocator.free(lin);
    try std.testing.expectEqualSlices(f64, &[_]f64{ 0, 10, 20, 30, 40 }, lin);

    const exp = try exponentialBuckets(std.testing.allocator, 1, 2, 5);
    defer std.testing.allocator.free(exp);
    try std.testing.expectEqualSlices(f64, &[_]f64{ 1, 2, 4, 8, 16 }, exp);
}

test "token bucket refills over time and denies when empty" {
    var b = TokenBucket.init(10, 5, 0); // 10 capacity, 5 tokens/sec
    try std.testing.expect(b.tryAcquireAt(10, 0));
    try std.testing.expect(!b.tryAcquireAt(1, 0));

    // half a second later: +2.5 tokens
    try std.testing.expect(!b.tryAcquireAt(3, std.time.ns_per_s / 2));
    try std.testing.expectApproxEqAbs(@as(f64, 2.5), b.availableAt(std.time.ns_per_s / 2), 1e-9);

    // two full seconds later than that: refill caps at capacity
    const later = std.time.ns_per_s / 2 + 2 * std.time.ns_per_s;
    try std.testing.expect(b.tryAcquireAt(10, later));
    try std.testing.expect(!b.tryAcquireAt(1, later));
}

test "token bucket never partially consumes on a failed acquire" {
    var b = TokenBucket.init(5, 1, 0);
    try std.testing.expect(!b.tryAcquireAt(6, 0));
    try std.testing.expectApproxEqAbs(@as(f64, 5), b.availableAt(0), 1e-9);
}

test "sliding window limiter smooths across a window boundary" {
    const windowNs: u64 = std.time.ns_per_s;
    var lim = SlidingWindowLimiter.init(10, windowNs, 0);

    var i: usize = 0;
    while (i < 10) : (i += 1) try std.testing.expect(lim.allowAt(0));
    try std.testing.expect(!lim.allowAt(0)); // exhausted current window

    // Halfway into the next window: previous window's 10 requests are
    // weighted at 50% overlap (5), so only 5 more should be allowed before
    // the weighted total reaches the limit of 10.
    const halfwayNextWindow = windowNs + windowNs / 2;
    var allowed: usize = 0;
    i = 0;
    while (i < 20) : (i += 1) {
        if (lim.allowAt(halfwayNextWindow)) allowed += 1;
    }
    try std.testing.expectEqual(@as(usize, 5), allowed);
}

test "sliding window limiter resets fully after a gap of more than one window" {
    const windowNs: u64 = std.time.ns_per_s;
    var lim = SlidingWindowLimiter.init(3, windowNs, 0);
    try std.testing.expect(lim.allowAt(0));
    try std.testing.expect(lim.allowAt(0));
    try std.testing.expect(lim.allowAt(0));
    try std.testing.expect(!lim.allowAt(0));

    // Jump 10 windows ahead: previous window count must not leak in.
    const farFuture = 10 * windowNs;
    try std.testing.expect(lim.allowAt(farFuture));
    try std.testing.expect(lim.allowAt(farFuture));
    try std.testing.expect(lim.allowAt(farFuture));
    try std.testing.expect(!lim.allowAt(farFuture));
}

test "registry exports counters gauges and histograms as sorted prometheus text" {
    var c = MetricCounter{};
    c.incrBy(7);
    var g = Gauge{};
    g.set(2.5);
    const bounds = [_]f64{ 5, 10 };
    var h = try Histogram.init(std.testing.allocator, &bounds);
    defer h.deinit();
    h.observe(3);
    h.observe(8);

    var reg = Registry.init(std.testing.allocator);
    defer reg.deinit();
    try reg.registerCounter("requests_total", &c);
    try reg.registerGauge("temperature", &g);
    try reg.registerHistogram("latency", &h);
    try std.testing.expectEqual(@as(usize, 3), reg.count());

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try reg.exportText(std.testing.allocator, buf.writer());

    const text = buf.items;
    // sorted alphabetically: latency < requests_total < temperature
    try std.testing.expect(std.mem.indexOf(u8, text, "latency_bucket{le=\"5\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "latency_bucket{le=\"10\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "latency_bucket{le=\"+Inf\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "latency_sum 11") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "latency_count 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "requests_total 7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "temperature 2.5\n") != null);

    const latencyPos = std.mem.indexOf(u8, text, "latency_bucket").?;
    const requestsPos = std.mem.indexOf(u8, text, "requests_total").?;
    const temperaturePos = std.mem.indexOf(u8, text, "temperature").?;
    try std.testing.expect(latencyPos < requestsPos);
    try std.testing.expect(requestsPos < temperaturePos);
}

test "registry re-registering the same name overwrites rather than duplicating" {
    var c1 = MetricCounter{};
    c1.incrBy(1);
    var c2 = MetricCounter{};
    c2.incrBy(99);

    var reg = Registry.init(std.testing.allocator);
    defer reg.deinit();
    try reg.registerCounter("x", &c1);
    try reg.registerCounter("x", &c2);
    try std.testing.expectEqual(@as(usize, 1), reg.count());

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try reg.exportText(std.testing.allocator, buf.writer());
    try std.testing.expectEqualStrings("x 99\n", buf.items);
}

test "formatDbStats renders levels up to the deepest populated one" {
    var s = stats_mod.Stats{};
    s.memtableEntries = 3;
    s.memtableBytes = 128;
    s.sstableCount = 2;
    s.cacheHits = 9;
    s.cacheMisses = 1;
    s.levels[0].tables = 1;
    s.levels[0].entries = 10;
    s.levels[2].tables = 4;
    s.levels[2].entries = 40;

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try formatDbStats(buf.writer(), "cobalt", s);

    const text = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, text, "cobalt_memtable_entries 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "cobalt_cache_hit_rate 0.900000\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "cobalt_level_tables{level=\"0\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "cobalt_level_tables{level=\"2\"} 4\n") != null);
    // level 1 is empty but must still appear since deepestLevel is 2
    try std.testing.expect(std.mem.indexOf(u8, text, "cobalt_level_tables{level=\"1\"} 0\n") != null);
    // level 3+ must not appear at all
    try std.testing.expect(std.mem.indexOf(u8, text, "level=\"3\"") == null);
}
