const std = @import("std");
const net_security = @import("net_security.zig");

pub const Error = std.mem.Allocator.Error || error{InvalidSearchBaseUrl};

pub fn isValid(raw: []const u8) bool {
    return validated(raw) != null;
}

pub fn normalizeEndpoint(allocator: std.mem.Allocator, raw: []const u8) Error![]u8 {
    const base_url = validated(raw) orelse return error.InvalidSearchBaseUrl;
    if (std.mem.endsWith(u8, base_url, "/search")) {
        return allocator.dupe(u8, base_url);
    }
    return std.fmt.allocPrint(allocator, "{s}/search", .{base_url});
}

fn validated(raw: []const u8) ?[]const u8 {
    var trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return null;

    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '/') {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }

    const uri = std.Uri.parse(trimmed) catch return null;
    if (uri.query != null or uri.fragment != null) return null;

    const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
    if (!is_https and !is_http) return null;

    const host_component = uri.host orelse return null;
    const host = switch (host_component) {
        .raw => |h| h,
        .percent_encoded => |h| blk: {
            if (std.mem.indexOfScalar(u8, h, '%') != null) return null;
            break :blk h;
        },
    };
    if (host.len == 0) return null;
    if (host[0] == ':') return null;
    if (std.mem.indexOfAny(u8, host, " \t\r\n") != null) return null;

    if (host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return null;
        if (close != host.len - 1) return null;
    }

    if (uri.port) |port| {
        if (port == 0) return null;
    }

    if (is_http and !net_security.isLocalHost(host)) return null;

    const path = switch (uri.path) {
        .raw => |p| p,
        .percent_encoded => |p| p,
    };
    if (path.len > 0 and !std.mem.eql(u8, path, "/search")) return null;

    return trimmed;
}

test "isValid accepts valid https URL" {
    try std.testing.expect(isValid("https://example.com"));
    try std.testing.expect(isValid("https://searx.example.com/search"));
}

test "isValid rejects empty string" {
    try std.testing.expect(!isValid(""));
    try std.testing.expect(!isValid("   "));
}

test "isValid rejects http for non-localhost" {
    try std.testing.expect(!isValid("http://example.com"));
    try std.testing.expect(!isValid("http://searx.example.com/search"));
}

test "isValid accepts http for localhost" {
    try std.testing.expect(isValid("http://localhost"));
    try std.testing.expect(isValid("http://localhost:8888"));
    try std.testing.expect(isValid("http://127.0.0.1:8888/search"));
}

test "isValid rejects unknown schemes" {
    try std.testing.expect(!isValid("ftp://example.com"));
    try std.testing.expect(!isValid("file:///etc/passwd"));
}

test "isValid rejects URLs with query or fragment" {
    try std.testing.expect(!isValid("https://example.com?q=test"));
    try std.testing.expect(!isValid("https://example.com#section"));
}

test "normalizeEndpoint appends /search when missing" {
    const allocator = std.testing.allocator;
    const result = try normalizeEndpoint(allocator, "https://example.com");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("https://example.com/search", result);
}

test "normalizeEndpoint preserves existing /search" {
    const allocator = std.testing.allocator;
    const result = try normalizeEndpoint(allocator, "https://example.com/search");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("https://example.com/search", result);
}

test "normalizeEndpoint returns error for invalid URL" {
    try std.testing.expectError(error.InvalidSearchBaseUrl, normalizeEndpoint(std.testing.allocator, ""));
    try std.testing.expectError(error.InvalidSearchBaseUrl, normalizeEndpoint(std.testing.allocator, "ftp://bad"));
}
