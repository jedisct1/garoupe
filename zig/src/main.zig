const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const math = std.math;
const mem = std.mem;
const Vector = std.meta.Vector;

const HalfState = Vector(8, u32);

const State = struct {
    x: HalfState,
    y: HalfState,

    fn init(key: [32]u8, nonce: [20]u8) State {
        var state = State{
            .x = HalfState{
                0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
            },
            .y = HalfState{
                0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
            },
        };
        for (mem.asBytes(&state.x)[0..key.len]) |*x, i| {
            x.* ^= key[i];
        }
        for (mem.asBytes(&state.y)[0..nonce.len]) |*y, i| {
            y.* ^= nonce[i];
        }
        var i: usize = 0;
        while (i < 20) : (i += 1) {
            state.update(i, i);
        }
        return state;
    }

    fn as64(state: *State) *[8]u64 {
        return @ptrCast(*[8]u64, state);
    }

    fn as128(state: *State) *[4]u128 {
        return @ptrCast(*[4]u128, state);
    }

    const rc = Vector(8, u32){ 0xb7e15162, 0xbf715880, 0x38b4da56, 0x324e7738, 0xbb1185eb, 0x4f7c7b57, 0xcfbfa1c8, 0xc2b3293d };

    fn sbox(state: *State) void {
        const x = &state.x;
        const y = &state.y;
        x.* +%= math.rotr(HalfState, y.*, 31);
        y.* +%= math.rotr(HalfState, x.*, 24);
        x.* ^= rc;
        x.* +%= math.rotr(HalfState, y.*, 17);
        y.* +%= math.rotr(HalfState, x.*, 17);
        x.* ^= rc;
        x.* +%= y.*;
        y.* +%= math.rotr(HalfState, x.*, 31);
        x.* ^= rc;
        x.* +%= math.rotr(HalfState, y.*, 24);
        y.* +%= math.rotr(HalfState, x.*, 16);
        x.* ^= rc;
    }

    fn update(state: *State, d1: u64, d2: u64) void {
        const state_p = state.as64().*;
        state.sbox();
        var state64 = state.as64();
        for (state64) |*x, i| {
            x.* ^= state_p[(i -% 1) % 8];
        }
        state64[0] ^= d1;
        state64[4] ^= d2;
    }

    fn enc(state: *State, dst: *[16]u8, src: *const [16]u8) void {
        const m = mem.readIntSliceLittle(u128, src);
        var state128 = state.as128();
        const c = m ^ state128[1] ^ state128[3];
        mem.writeIntLittle(u128, dst, c);
        state.update(@truncate(u64, m), @truncate(u64, m >> 64));
    }

    fn dec(state: *State, dst: *[16]u8, src: *const [16]u8) void {
        const c = mem.readIntSliceLittle(u128, src);
        var state128 = state.as128();
        const m = c ^ state128[1] ^ state128[3];
        mem.writeIntLittle(u128, dst, m);
        state.update(@truncate(u64, m), @truncate(u64, m >> 64));
    }

    fn mac(state: *State, adlen: usize, mlen: usize) [16]u8 {
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            state.update(adlen, mlen);
        }
        var tag: [16]u8 = undefined;
        var state128 = state.as128();
        mem.writeIntLittle(u128, &tag, state128[0] ^ state128[1] ^ state128[2] ^ state128[3]);
        return tag;
    }
};

pub const Garoupe256 = struct {
    pub const key_length: usize = 32;
    pub const nonce_length: usize = 20;
    pub const tag_length: usize = 16;

    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
        debug.assert(c.len == m.len);
        var state = State.init(key, npub);
        var src: [16]u8 align(16) = undefined;
        var dst: [16]u8 align(16) = undefined;
        var i: usize = 0;
        while (i + 16 <= ad.len) : (i += 16) {
            state.enc(&dst, ad[i..][0..16]);
        }
        if (ad.len % 16 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. ad.len % 16], ad[i .. i + ad.len % 16]);
            state.enc(&dst, &src);
        }
        i = 0;
        while (i + 16 <= m.len) : (i += 16) {
            state.enc(c[i..][0..16], m[i..][0..16]);
        }
        if (m.len % 16 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. m.len % 16], m[i .. i + m.len % 16]);
            state.enc(&dst, &src);
            mem.copy(u8, c[i .. i + m.len % 16], dst[0 .. m.len % 16]);
        }
        tag.* = state.mac(ad.len, m.len);
    }

    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) !void {
        debug.assert(c.len == m.len);
        var state = State.init(key, npub);
        var src: [16]u8 align(16) = undefined;
        var dst: [16]u8 align(16) = undefined;
        var i: usize = 0;
        while (i + 16 <= ad.len) : (i += 16) {
            state.enc(&dst, ad[i..][0..16]);
        }
        if (ad.len % 16 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. ad.len % 16], ad[i .. i + ad.len % 16]);
            state.enc(&dst, &src);
        }
        i = 0;
        while (i + 16 <= m.len) : (i += 16) {
            state.dec(m[i..][0..16], c[i..][0..16]);
        }
        if (m.len % 16 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. m.len % 16], c[i .. i + m.len % 16]);
            state.dec(&dst, &src);
            mem.copy(u8, m[i .. i + m.len % 16], dst[0 .. m.len % 16]);
            mem.set(u8, dst[0 .. m.len % 16], 0);
            var state64 = state.as64();
            state64[0] ^= mem.readIntLittle(u64, dst[0..8]);
            state64[4] ^= mem.readIntLittle(u64, dst[8..16]);
        }
        const computed_tag = state.mac(ad.len, m.len);
        if (!crypto.utils.timingSafeEql([16]u8, computed_tag, tag)) {
            mem.set(u8, m, 0xaa);
            return error.AuthenticationFailed;
        }
    }
};

test "Garoupe256 test with random inputs" {
    var key: [Garoupe256.key_length]u8 = undefined;
    var nonce: [Garoupe256.nonce_length]u8 = undefined;
    var ad: [20]u8 = undefined;
    var m: [100]u8 = undefined;

    crypto.random.bytes(&key);
    crypto.random.bytes(&nonce);
    crypto.random.bytes(&ad);
    crypto.random.bytes(&m);

    var tag: [Garoupe256.tag_length]u8 = undefined;
    var c: [m.len]u8 = undefined;
    Garoupe256.encrypt(&c, &tag, &m, &ad, nonce, key);

    var m2: [m.len]u8 = undefined;
    try Garoupe256.decrypt(&m2, &c, tag, &ad, nonce, key);
    debug.assert(mem.eql(u8, &m, &m2));

    c[0] +%= 1;
    if (Garoupe256.decrypt(&m2, &c, tag, &ad, nonce, key)) debug.assert(false) else |_| {}
    c[0] -%= 1;

    key[0] +%= 1;
    if (Garoupe256.decrypt(&m2, &c, tag, &ad, nonce, key)) debug.assert(false) else |_| {}
    key[0] -%= 1;

    ad[0] +%= 1;
    if (Garoupe256.decrypt(&m2, &c, tag, &ad, nonce, key)) debug.assert(false) else |_| {}
    ad[0] -%= 1;
}

test "Garoupe256 test vector" {
    const key = [_]u8{0x01} ** Garoupe256.key_length;
    const nonce = [_]u8{0x02} ** Garoupe256.nonce_length;
    const ad = [_]u8{0x03} ** 20;
    const m = [_]u8{0x04} ** 100;

    var tag: [Garoupe256.tag_length]u8 = undefined;
    var c: [m.len]u8 = undefined;
    Garoupe256.encrypt(&c, &tag, &m, &ad, nonce, key);

    var m2: [m.len]u8 = undefined;
    try Garoupe256.decrypt(&m2, &c, tag, &ad, nonce, key);
    debug.assert(mem.eql(u8, &m, &m2));

    var expected_c: [c.len]u8 = undefined;
    var expected_tag: [tag.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_c, "9ebd0cba7f8e8f2248e724d536558926497724bbaf9f7e2c488c571916de00b12e9712313732c9bdcf4adb4ca1508660190757ea6fcf0476b8312696e8236cc706d46ce95aa21fbe7cc52a88233b343a86f5ef16b2ebe6ae1849ad2c7a9cb03cabaf95b4");
    _ = try std.fmt.hexToBytes(&expected_tag, "46d8e9c4c9da3aef2bb9f484f965b320");
    debug.assert(mem.eql(u8, &expected_c, &c));
    debug.assert(mem.eql(u8, &expected_tag, &tag));
}
