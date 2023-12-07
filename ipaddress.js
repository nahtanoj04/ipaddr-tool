(function() {

function map(func, args) {
	var result = [];
	for(var i in args) {
		result.push(func(args[i]));
	}
	return result;
}

function map2(func, args) {
	var result = [];
	for(var i in args[0]) {
		result.push(func(args[0][i], args[1][i]));
	}
	return result;
}

function reduce(func, arg, init) {
	var prev = init;
	for (var i in arg) {
		prev = func(prev, arg[i]);
	}
	return prev;
}

function buildArray(value, n) {
	var result = [];
	for (var i = 0; i < n; ++i) {
		result.push(value);
	}
	return result;
}

function hex(x) {
	return x.toString(16);
}

// http://stackoverflow.com/a/1267338/156521
function zeroFill( number, width )
{
	width -= number.toString().length;
	if ( width > 0 )
	{
		return new Array( width + (/\./.test( number ) ? 2 : 1) ).join( '0' ) + number;
	}
	return number + ""; // always return a string
}

// http://ejohn.org/blog/fast-javascript-maxmin/
Array.max = function( array ){
	return Math.max.apply( Math, array );
};
 
Array.min = function( array ){
	return Math.min.apply( Math, array );
};

function _applyMask(address, mask) {
	return map2(function(address, mask) { return address & mask; }, [address, mask]);
}

function _merge(a, b) {
	return map2(function(address, mask) { return address | mask; }, [a, b]);
}

function _buildBinaryMask6(n) {
	return _buildBinaryMask(n, 16, 8, 0xffff);
}

function _buildBinaryMask4(n) {
	return _buildBinaryMask(n, 8, 4, 0xff);
}

/**
 * Creates an array of chunks (16 bits v6, 8 bits v4) with the correct
 * number of leading bits set according to the subnet mask.
 */
function _buildBinaryMask(n, chunkSize, chunks, chunkMask) {
	var mask = buildArray(chunkMask, Math.floor(n/chunkSize));
	if (n % chunkSize != 0) {
		var leastSignificantChunk = chunkMask ^ ((1 << (chunkSize - (n % chunkSize))) - 1);
		mask = mask.concat(leastSignificantChunk);
	}
	return mask.concat(buildArray(0, chunks-mask.length));
}

function _invertMask4(mask) {
	return _invertMask(mask, 0xff);
}

function _invertMask6(mask) {
	return _invertMask(mask, 0xffff);
}

/**
 * Flip bits of an array of chunks.
 */
function _invertMask(mask, chunkMask) {
	return map(function(x) { return chunkMask ^ x; }, mask);
}

var IPAddress = function(text) {
	this._address = [];
	this._mask = [];
	if (text) {
		this._parse(text);
	}
};
IPAddress.prototype.address = function() {
	throw 3.14;
};
IPAddress.prototype.mask = function() {
	return this._mask;
};
IPAddress.prototype.cidr = function() {
	return this.address() + '/' + this.mask();
};
IPAddress.prototype.applyMask = function(address) {
	// build an object out of a string, if necessary
	address = this._strToObj(address);
	// create a mask to apply to self
	var mask = this._buildBinaryMask(this._mask);
	// invert the mask to apply to the other address
	var notMask = this._invertMask(mask);
	var result = this._newEmptyObj();
	// apply mask to self, invert mask to other, and then merge (OR)
	result._address = _merge(
		_applyMask(this._address, mask),
		_applyMask(address._address, notMask));
	// assign the new object's mask from self
	result._mask = this._mask;
	return result;
};
IPAddress.prototype.binaryMask = function() {
	var mask = this._buildBinaryMask(this._mask);
	var obj = this._newEmptyObj();
	obj._address = mask;
	return obj;
};

IPAddress.prototype.equals = function(rhs) {
	if (this._mask != rhs._mask)
		return false;
	for (var i in this._address) {
		if (this._address[i] != rhs._address[i])
			return false;
	}
	return true;
};

/**
 * Check to see if the subnet portion of our address is the
 * same as the subnet portin of the other address. The Subnet
 * length from self is used for both addresses.
 */
IPAddress.prototype.subnetContains = function(rhs) {
	var mask = this._buildBinaryMask(this._mask);
	var me = _applyMask(this._address, mask);
	var him = _applyMask(rhs._address, mask);
	for (var i in me) {
		if (me[i] != him[i])
			return false;
	}
	return true;
};

IPAddress.prototype.rangeMin = function() {
	var mask = this._buildBinaryMask(this._mask);
	var network = _applyMask(this._address, mask);
	var obj = this._newEmptyObj();
	obj._address = network;
	obj._mask = this._mask;
	return obj;
};
IPAddress.prototype.rangeMax = function() {
	var mask = this._buildBinaryMask(this._mask);
	var addr = _applyMask(this._address, mask);
	mask = this._invertMask(mask);
	addr = _merge(addr, mask);
	var obj = this._newEmptyObj();
	obj._address = addr;
	obj._mask = this._mask;
	return obj;
};

var IPv4Address = function(src) {
	if (typeof(src) == 'string') {
		IPAddress.call(this, src);
	} else if (typeof(src) == 'object') {
		IPAddress.call(this, src[0]);
		this._parseMask(src[1]);
	}
};
IPv4Address.prototype = new IPAddress();
IPv4Address.prototype._parse = function(text) {
	var addrMatch = /([0-9\.]+)(\/[0-9\.]+)?/.exec(text);
	if (addrMatch)
		this._parseAddress(addrMatch[1]);
	else
		throw 'Invalid characters in address.';

	var maskMatch = addrMatch[2];
	if (maskMatch && maskMatch.indexOf('.') != -1)
		this._parseMask(maskMatch.substr(1));
		// get rid of the slash at the beginning
	else if (maskMatch)
		this._mask = parseInt(maskMatch.substr(1));
	else
		this._mask = 0;
	if (this._mask < 0 || this._mask > 32)
		throw 'Invalid mask value';
	if (this._address.length != 4)
		throw 'Invalid v4 address size';
};

IPv4Address.prototype._parseAddress = function(text) {
	var octets = text.split('.');
	if (octets.length != 4)
		throw 'Address must be exactly 4 octets.';
	this._address = map(parseInt, octets);
	if (Array.max(this._address) > 255)
		throw 'Octet out of range.';
	if (Array.min(this._address) < 0)
		throw 'Octet out of range.';
};

IPv4Address.prototype._parseMask = function(text) {
	var octets = text.split('.');
	if (octets.length != 4)
		throw 'Address must be exactly 4 octets.';

	var valid_masks = [0, 128, 192, 224, 240, 248, 252, 254, 255];
	function parse(val) {
		var val = parseInt(val)
		if (valid_masks.indexOf(val) == -1)
			throw 'Invalid octect ' + val + ' for a v4 mask';
		return val;
	}
	var mask = map(parse, octets);

	function check(prev, val) {
		if (prev != null && val > prev)
			throw 'Invalid mask';
		return val;
	}
	reduce(check, mask);

	function bitsoncount(x) {
		var b = 0;
		while (x > 0) {
			x &= x - 1;
			b += 1;
		}
		return b;
	}

	function sumbits(prev, val) {
		return prev + bitsoncount(val);
	}

	this._mask = reduce(sumbits, mask, 0);
};

IPv4Address.prototype._strToObj = function(address) {
	if (!(address instanceof IPv4Address))
		address = new IPv4Address(address);
	return address;
};

IPv4Address.prototype._newEmptyObj = function() {
	return new IPv4Address();
}

IPv4Address.prototype._buildBinaryMask = function(mask) {
	return _buildBinaryMask4(mask);
}

IPv4Address.prototype._invertMask = function(mask) {
	return _invertMask4(mask);
}

IPv4Address.prototype.address = function() {
	return map(function(x) { return x.toString(); }, this._address).join('.');
}

IPv6Address = function(text) {
	IPAddress.call(this, text);
};
IPv6Address.prototype = new IPAddress();


IPv6Address.prototype._parse = function(text) {
	var addrMatch = /^([0-9a-f:]+)(\/\d+)?$/.exec(text);
	if (addrMatch)
		this._parseAddress(addrMatch[1]);
	else
		throw'Invalid character in address.';

	var maskMatch = /\/(\d{1,3})/.exec(text);
	if (maskMatch)
		this._mask = parseInt(maskMatch[1]);
	else
		this._mask = 0;
	if (this._mask < 0 || this._mask > 128)
		throw 'Invalid mask value';
	if (this._address.length != 8)
		throw 'Invalid v4 address size';
};

IPv6Address.prototype._parseAddress = function(text) {
	// Parse the address one side of a :: at a time
	var parts = text.split('::');

	function _parseChunks(part) {
		// if there's nothing on this side of the ::, return
		if (part.length == 0)
			return [];
		var chunks = part.split(':');
		// you can only have 8 chunks at most
		if (chunks.length > 8)
			throw 'Address is too long';
		// parse the chunks with int-base-16
		return map(function(chunk) {
			var x = parseInt(chunk, 16);
			if (isNaN(x))
				throw 'bad split'
			if (x > 0xffff || x < 0)
				throw 'IPv6Address chunk out of range';
			return x;
		}, chunks);
	}

	// if there are multuple ::'s, then something is wrong
	if (parts.length > 2)
		throw 'Only one :: allowed';

	// parse the left side of the ::
	var addr = _parseChunks(parts[0]);
	// if there is a right side, parse it
	if (parts.length == 2) {
		var last = _parseChunks(parts[1]);
		var zeroChunks = (8 - addr.length - last.length);
		// if were are inside this block there was a ::
		// a :: must abbreviate no less than 2 runs of zeros
		if (zeroChunks < 2)
			throw 'Invalid use of ::';
		addr = addr.concat(buildArray(0, zeroChunks));
		addr = addr.concat(last);
	}

	this._address = addr;
};

IPv6Address.prototype.address = function() {
	function max_index(l) {
		return l.indexOf(Array.max(l));
	}

	var saddr = reduce(
		function(prev, char) {
			return prev + ':' + char.toString(16);
		},
		this._address, '');
	var matches = [], result, re = /(:0){2,8}/g;
	while (result = re.exec(saddr)) {
		matches.push(result);
	}
	if (matches.length > 0) {
		var match = matches[max_index(map(function(x) {
			return x[0].length;
		}, matches))];
		var start = match.index;
		var stop = match[0].length + start;
		saddr = saddr.slice(0,start) + ':' + saddr.slice(stop);
	}
	saddr = saddr.slice(1);
	saddr = saddr.replace(/^:([0-9a-f])/, '::$1');
	saddr = saddr.replace(/([0-9a-f]):$/, '$1::');
	return saddr;
};

IPv6Address.prototype.embeddedMacAddress = function() {
	if (
		(this._address[5] & 0x00ff) == 0x00ff &&
		(this._address[6] & 0xff00) == 0xfe00) {
		var str = '';
		str += zeroFill(hex(((this._address[4] & 0xff00) ^ (0x0200)) >> 8), 2);
		str += ':';
		str += zeroFill(hex(this._address[4] & 0x00ff), 2);
		str += ':';
		str += zeroFill(hex((this._address[5] & 0xff00) >> 8), 2);
		str += ':';
		str += zeroFill(hex(this._address[6] & 0x00ff), 2);
		str += ':';
		str += zeroFill(hex((this._address[7] & 0xff00) >> 8), 2);
		str += ':';
		str += zeroFill(hex(this._address[7] & 0x00ff), 2);
		return str;
	} else {
		return null;
	}
};

IPv6Address.prototype._strToObj = function(address) {
	if (! (address instanceof IPv6Address))
		address = new IPv6Address(address);
	return address;
};

IPv6Address.prototype._newEmptyObj = function() {
	return new IPv6Address();
};

IPv6Address.prototype._buildBinaryMask = function(mask) {
	return _buildBinaryMask6(mask);
};

IPv6Address.prototype._invertMask = function(mask) {
	return _invertMask6(mask);
};

function calc6rd(v6, v4) {
	v6 = new IPv6Address(v6);
	v4 = new IPv4Address(v4);
	v6._address = _applyMask(v6._address, v6.binaryMask()._address);
	v4._address = _applyMask(v4._address, _invertMask4(v4.binaryMask()._address));
	var v4offset = v6.mask() - v4.mask();
	var prefix_len = v6.mask() + (32 - v4.mask());
	var bits = [];
	for (var i = 0; i < 128; ++i) {
		var v4bit = i - v4offset;
		bits[i] = !!(v6._address[Math.floor(i/16)] & (1 << (15-(i%16))));
		if (v4bit >= 0 && v4bit <= 32)
			bits[i] |= !!(v4._address[Math.floor(v4bit/8)] & (1 << (7-(v4bit%8))));
	}
	var address = [0, 0, 0, 0, 0, 0, 0, 0];
	for (var i = 0; i < 128; ++i) {
		if (bits[i])
			address[Math.floor(i/16)] |= (1 << (15-(i%16)));
	}
	v6 = new IPv6Address();
	v6._address = address;
	v6._mask = prefix_len;
	return v6;
}
window.calc6rd = calc6rd;

function assert(bool) {
	if (!bool)
		throw "you failed the test!";
}

function test6() {
	function test(text) {
		console.log("test:", text);
		var v6 = new IPv6Address(text);
		var cidr = v6.cidr();
		console.log(text);
		console.log(cidr);
		assert(cidr == text);
		console.log("");
	}

	function test_fail(text) {
		console.log("should fail :", text);
		var failure = false;
		try {
			v6 = new IPv6Address(text);
		} catch(e) {
			failure = true;
			console.log("fail message:", toString(e));
		}
		if (!failure)
			console.log("false       :", v6.cidr());
		assert(failure);
		console.log('');
	}

	function normalize_test(test, expected) {
		console.log("normalize test:");
		console.log(test);
		var v6 = new IPv6Address(test);
		var addr = v6.address();
		console.log(addr);
		console.log(expected);
		assert (addr == expected);
		console.log("");
	}

	function mask_test(prefix, suffix, expected) {
		prefix = new IPv6Address(prefix);
		suffix = new IPv6Address(suffix);
		expected = new IPv6Address(expected);
		var result = prefix.applyMask(suffix);
		console.log("prefix  :", prefix.cidr());
		console.log("suffix  :", suffix.cidr());
		console.log("expected:", expected.cidr());
		console.log("result  :", result.cidr());
		assert(result.equals(expected));
		console.log('');
	}

	function subnetContains_test(a, b, expected) {
		a = new IPv6Address(a);
		b = new IPv6Address(b);
		console.log('subnet :', a.cidr());
		console.log('address:', b.address());
		console.log('mask   :', map(hex, _buildBinaryMask6(a.mask())));
		if (expected)
			console.log('contained');
		else
			console.log('not contained');
		assert(a.subnetContains(b) == expected)
		console.log('');
	}


	test('::1/128');
	test('fe80::a00:27ff:fe32:a587/64');
	test('2003:d025:a25:5250:a982:fae8:59eb:3001/64');
	test('::1:0:0:0:1/0');
	test('0:0:1::1/0');
	test('2003:d025:a25:5250::/0');

	test_fail('2003:d025:a25:5250:a982:fae8:59eb:3001:abcd:ef01/64');
	test_fail('2003:d025:a25:5250:a982:fae8::abcd:ef01:1/64');
	test_fail('2003:d025:a25:5250:a982:fae8::abcd:ef01/64');

	normalize_test('00:0:0:1:0:0:0:1', '::1:0:0:0:1');
	normalize_test('00:0:1:0:0:0:0:1', '0:0:1::1');
	normalize_test('a:b:0000c:0:0::1', 'a:b:c::1');

	mask_test('2003:d025:a25:5250::/64', 'fe80::a00:27ff:fe32:a587/64',
		'2003:d025:a25:5250:a00:27ff:fe32:a587/64');
	mask_test('2003:d025:a25:5250::/48', 'fe80::a00:27ff:fe32:a587/64',
		'2003:d025:a25:0:a00:27ff:fe32:a587/48');
	mask_test('2001::/32', '::a00:27ff:fe32:a587',
		'2001::a00:27ff:fe32:a587/32');
	mask_test('2003:d025:a25:5250::/72', 'fe80::a00:27ff:fe32:a587/64',
		'2003:d025:a25:5250:0:27ff:fe32:a587/72');

	subnetContains_test('::1/128', '::1/128', true);
	subnetContains_test('::1/127', '::11', false);
	subnetContains_test('1::1/128', '::1/128', false);
	subnetContains_test('2003:d025:a25:5250:a982:fae8:59eb:3001/64',
		'2003:d025:a25:5250::/64', true);
	subnetContains_test('2003:d125:a25:5250:a982:fae8:59eb:3001/64',
		'2003:d025:a25:5250::/64', false);
	subnetContains_test('2003:d025:a25:5250:a982:fae8:59eb:3002/64',
		'2003:d025:a25:5250::/64', true);
	subnetContains_test('2003:d025:a25:5250:ffff:ffff:ffff:ffff/64',
		'2003:d025:a25:5250::/64', true);
	subnetContains_test('fc00::/7', 'fc01::', true);
	subnetContains_test('fc00::/7', 'fd00::', true);
	subnetContains_test('fc00::/7', 'ff01::', false);
}

function test4() {
	function test(text) {
		console.log("test:");
		var v4 = new IPv4Address(text);
		var cidr = v4.cidr();
		console.log(text);
		console.log(cidr);
		assert(cidr == text);
		console.log("");
	}

	function mask_test(prefix, suffix, expected) {
		prefix = new IPv4Address(prefix);
		suffix = new IPv4Address(suffix);
		expected = new IPv4Address(expected);
		var result = prefix.applyMask(suffix);
		console.log("prefix  :", prefix.cidr());
		console.log("suffix  :", suffix.cidr());
		console.log("expected:", expected.cidr());
		console.log("result  :", result.cidr());
		assert(result.equals(expected));
		console.log('');
	}

	function subnetContains_test(a, b, expected) {
		a = new IPv4Address(a);
		b = new IPv4Address(b);
		console.log('subnet :', a.cidr());
		console.log('address:', b.address());
		console.log('mask   :', map(hex, _buildBinaryMask4(a.mask())));
		if (expected)
			console.log('contained');
		else
			console.log('not contained');
		assert(a.subnetContains(b) == expected)
		console.log('');
	}

	function tupleTest(t, expected) {
		try {
			console.log('input   : ', t);
			console.log('expected: ', expected);
			var v4 = new IPv4Address(t);
			var cidr = v4.cidr()
			console.log('cidr    : ', cidr);
			if (expected != 'fail')
				assert(cidr == expected);
			else
				assert(False);
		} catch (e) {
			assert(expected == 'fail');
		}
	}

	test('127.0.0.1/32');
	mask_test('172.16.0.0/16', '0.0.255.1', '172.16.255.1/16');
	subnetContains_test('172.16.0.0/16', '172.16.255.1', true);
	subnetContains_test('172.16.0.0/16', '172.16.255.1', true);
	subnetContains_test('172.16.0.0/12', '172.31.255.1', true);
	subnetContains_test('172.16.0.0/12', '172.32.255.1', false);

	tupleTest(['192.168.1.64', '255.255.255.0'], '192.168.1.64/24');
	tupleTest(['192.168.1.64', '255.255.0.255'], 'fail');
	tupleTest(['192.168.1.64', '255.255.255.127'], 'fail');
	tupleTest(['192.168.1.64', '255.255.254.0'], '192.168.1.64/23');
	tupleTest(['192.168.1.64', '255.255.252.0'], '192.168.1.64/22');
	tupleTest(['192.168.1.64', '255.255.248.0'], '192.168.1.64/21');
	tupleTest(['192.168.1.64', '255.255.240.0'], '192.168.1.64/20');
	tupleTest(['192.168.1.64', '255.255.224.0'], '192.168.1.64/19');
	tupleTest(['192.168.1.64', '255.255.192.0'], '192.168.1.64/18');
	tupleTest(['192.168.1.64', '255.255.128.0'], '192.168.1.64/17');
	tupleTest(['192.168.1.64', '255.255.0.0'], '192.168.1.64/16');
	tupleTest(['192.168.1.64', '255.0.0.0'], '192.168.1.64/8');
	tupleTest(['192.168.1.64', '128.0.0.0'], '192.168.1.64/1');
}

////

window.IPv4Address = IPv4Address;
window.IPv6Address = IPv6Address;

//test6();
//test4();

})();
