//We need the JsPanel "class", so try to load it if it's not here
if (typeof JsPanel == "undefined") {
	var head = document.getElementsByTagName('head')[0];
	var script = document.createElement('script');
	script.type = 'text/javascript';
	script.src = 'JsPanel.js';
	head.appendChild(script);
}

// While that's loading, define our "class"
function JsSubnet(options) {
	this.options = options;
	this.objlist = {
		ip: null,
		mask: null,
		net: null,
		bits: null,
		broadcast: null,
		ipcount: null,
		usable: null,
		first: null,
		last: null,
		cidrstartip: null,
		cidrendip: null,
		cidrlist: null
	};
	this.objlabels = {
		ip: 'IP: ',
		mask: 'Mask: ',
		net: 'Routing Prefix: ',
		bits: 'Network Bits: /',
		broadcast: 'Broadcast Address: ',
		ipcount: 'IP Addresses: ',
		usable: 'Usable IP Addresses: ',
		first: 'First Usable IP: ',
		last: 'Last Usable IP: ',
		cidrstartip: 'Start IP: ',
		cidrendip: 'End IP: ',
		cidrlist: 'CIDR Networks: '
	};
	this.updatelock = false;
	this.ipaddress = "";
	this.maskbits = 32;
	this.network = "";
	this.broadcast = "";
	this.ipcount = 0;
	this.usable = 0;
	this.first = "";
	this.last = "";
	this.panel = null;
};

JsSubnet.prototype.setObj = function (id,obj)
{
	if (typeof id != "string") throw "setObj(" + [].slice.call(arguments).join(',') + "): Invalid id";
	if (obj == undefined || obj == null) throw "setObj(" + [].slice.call(arguments).join(',') + "): Object required";
	if (!(id in this.objlist)) throw "getObjects(" + [].slice.call(arguments).join(',') + "): Unknown object " + id;
	if (typeof obj == "string") {
		this.objlist[id] = document.getElementById(obj);
	} else {
		this.objlist[id] = obj;
	}
	if (this.objlist[id] == null) {
		this.objlist[id] = { value: null };
	}
	return this.objlist[id];

}

JsSubnet.prototype.getObjects = function (idlist)
{
	if (typeof idlist != "object" || idlist.length < 1 ) throw "getObjects(" + [].slice.call(arguments).join(',') + "): argument must be an array";
	try {
		for (var key in idlist) {
			this.setObj(key,idlist[key]);
		}
	} catch (e) {
		if (typeof e == "string") e = "getObjects(" + [].slice.call(arguments).join(',') + "): " + e;
	}
}

JsSubnet.prototype.getVal = function (id)
{
	if (!((typeof id == "string") && (id in this.objlist))) throw "getVal(" + [].slice.call(arguments).join(',') + "): Invalid id";
	if (this.objlist[id] === null) return;
	if ('value' in this.objlist[id]) return this.objlist[id].value;
	if ('innerHTML' in this.objlist[id]) return this.objlist[id].innerHTML;
	return undefined;

}

JsSubnet.prototype.setLabel = function (id,lbl)
{
	if (typeof id != "string"  || !(id in this.objlabel))  throw "setVal(" + [].slice.call(arguments).join(',') + "): Invalid id " + id;
	this.objlabel[id] = lbl;
}

JsSubnet.prototype.setVal = function (id,val)
{
	if (typeof id != "string"  || !(id in this.objlist))  throw "setVal(" + [].slice.call(arguments).join(',') + "): Invalid id " + id;
	if (this.objlist[id] === null) return;
	try {
		this.updatelock = true;
		if ('value' in this.objlist[id]) {
			this.objlist[id].value = val;
		} else if ('innerHTML' in this.objlist[id]) {
			this.objlist[id].innerHTML = val;
		}
		this.updatelock = false;
	} catch(e) {
		this.updatelock = false;
		throw e;
	}
}

JsSubnet.prototype.dec2bin = function (dec)
{
	if (typeof dec != "number") throw "dec2bin(" + [].slice.call(arguments).join(',') + "): argument must be a number";
	var bin = "";
	var curdec = dec;
	while (curdec != 0) {
		bin = Math.abs(curdec % 2) + bin;
		if (curdec < 0) {
			curdec = Math.ceil(curdec/2);
		} else {
			curdec = Math.floor(curdec/2);
		}
	}
	return bin
}

JsSubnet.prototype.bin2dec = function (bin)
{
	if (typeof bin != "string") throw "bin2dec(" + [].slice.call(arguments).join(',') + "): argument must be a string";
	if (bin.match(/[^01]/)) throw "bin2dec(" + [].slice.call(arguments).join(',') + "): argument may only contain '0' and '1'";
	var dec=0;
	for(var i=0; i<bin.length; i++) {
		if (dec != undefined) {
			dec = dec * 2;
			if (bin[i] == "1") {
				dec += 1;
			} else {
				if (bin[i] != 0) { dec = undefined; }
			}
		}
	}
	return dec;
}

JsSubnet.prototype.and = function (a,b)
{
	if (typeof a != "number" || typeof b != "number") throw "and(" + [].slice.call(arguments).join(',') + "): arguments must be numbers";
	try {
		var bino = "";
		var bina = this.dec2bin(a);
		var binb = this.dec2bin(b);
		var mlen = bina.length;
		if (binb.length > mlen) { mlen = binb.length };
		while (bina.length < mlen) { bina = "0" + bina; }
		while (binb.length < mlen) { binb = "0" + binb; }
		for (var i=0; i<mlen; i++) {
			bino = bino + ((bina[i] == "1" && binb[i] == "1")?"1":"0");
		}
		return this.bin2dec(bino);
	} catch (e) {
		if (typeof e == "string") e = "and(" + [].slice.call(arguments).join(',') + "): " + e;
		throw e;
	}
}

JsSubnet.prototype.xor = function (a, b)
{
	if (typeof a != "number" || typeof b != "number") throw "xor(" + [].slice.call(arguments).join(',') + "): arguments must be numbers";
	try {
		var bino = "";
		var bina = this.dec2bin(a);
		var binb = this.dec2bin(b);
		var mlen = bina.length;
		if (binb.length > mlen) { mlen = binb.length };
		while (bina.length < mlen) { bina = "0" + bina; }
		while (binb.length < mlen) { binb = "0" + binb; }
		for (var i=0; i<mlen; i++) {
			bino = bino + ((bina[i] != binb[i])?"1":"0");
		}
		return this.bin2dec(bino);
	} catch (e) {
		if (typeof e == "string") e = "xor(" + [].slice.call(arguments).join(',') + "): " + e;
		throw e;
	}
}

JsSubnet.prototype.or = function (a,b)
{
	if (typeof a != "number" || typeof b != "number") throw "or(" + [].slice.call(arguments).join(',') + "): arguments must be numbers";
	try {
		var bino = "";
		var bina = this.dec2bin(a);
		var binb = this.dec2bin(b);
		var mlen = bina.length;
		if (binb.length > mlen) { mlen = binb.length };
		while (bina.length < mlen) { bina = "0" + bina; }
		while (binb.length < mlen) { binb = "0" + binb; } 
		for (var i=0; i<mlen; i++) {
			bino = bino + (((bina[i] == "1") || (binb[i] == "1"))?"1":"0");
		}
		return this.bin2dec(bino);
	} catch (e) {
		if (typeof e == "string") e = "or(" + [].slice.call(arguments).join(',') + "): " + e;
		throw e;
	}
}

JsSubnet.prototype.not = function (a, bitlen)
{
	if (typeof a != "number" || ( typeof bitlen != "number" && typeof bitlen != "undefined")) throw "not(" + [].slice.call(arguments).join(',') + "): arguments must be numbers";
	try {
		var bin = "";
		var bina = this.dec2bin(a);
		if (bitlen) {
			while (bina.length < bitlen) { bina = "0" + bina; }
		}
		for(var i=0; i<bina.length; i++){
			if (bina[i] == 1) {
				bin = bin + "0";
			} else {
				bin = bin + "1";
			}
		}
		return this.bin2dec(bin);
	} catch (e) {
		if (typeof e == "string") e = "not(" + [].slice.call(arguments).join(',') + "): " + e;
		throw e;

	}
}

JsSubnet.prototype.ip2dec = function (ip)
{
	if (typeof ip != "string") throw "ip2dec(" + [].slice.call(arguments).join(',') + "): argument must be string";
	var ipdec = 0;
	var ipmat = ip.match(/^[ ]*([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})[ \/]*$/); 
	if (ipmat) {
		for(var i=1; i<5; i++) {
			var octet = parseInt(ipmat[i]);
			if ((octet >= 0) && (octet <= 255)) {
				ipdec = ipdec * 256 + octet;
			} else {
				throw "ip2dec(" + [].slice.call(arguments).join(',') + "): Invalid IP " + ip;
			}
		}
	} else {
		throw "ip2dec(" + [].slice.call(arguments).join(',') + "): argument must be in dotted-decimal format";
	}
	return ipdec;
}

JsSubnet.prototype.dec2ip = function (dec)
{
	if (typeof dec != "number") dec = parseInt(dec);
	if (typeof dec != "number" || dec < 0) throw "dec2ip(" + [].slice.call(arguments).join(',') + "): Invalid argument: " + dec;
	var ip = "";
	var curdec = dec;
	for (var i=0; i<4; i++){
		if (ip != "") { ip = "." + ip; }
		ip = (curdec % 256) + ip;
		curdec = Math.floor(curdec / 256);
	}
	if (curdec != 0) throw "dec2ip(" + [].slice.call(arguments).join(',') + "): Error converting " + dec + " to IP address";
	return ip;

}

JsSubnet.prototype.mask2bits = function (netmask)
{
	mask = 0;
	var ipmat
		if (typeof netmask == "string"  && (ipmat = netmask.match(/^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/))) {
			for(var i=0;i<4;i++){
				if ((mask != (i * 8)) && (ipmat[i+1] != 0)) { throw "mask2bits(" + [].slice.call(arguments).join(',') + "): Invalid mask " + netmask; }
				if (mask) {
					mask +=  (8-(Math.log(256 - ipmat[i + 1])/Math.log(2)));
				}                                                            
			} 
		} else {
			throw "mask2bits(" + [].slice.call(arguments).join(',') + "): Invalid mask " + netmask;
		}
	return mask;
}

JsSubnet.prototype.mask2dec = function (bits)
{
	if (bits == undefined) var bits = this.netmask;
	if (typeof bits != "number" || bits < 0 || bits > 32) throw "mask2dec(" + [].slice.call(arguments).join(',') + "): invalid argument " + bits;
	return (Math.pow(2,bits) - 1) * Math.pow(2,32 - bits);
}


JsSubnet.prototype.getNetDec = function (ip,mask)
{
	if (ip == undefined && mask == undefined) {
		ip = this.ipaddress;
		mask = this.maskbits;
	}
	if (typeof ip == "string") {
		ip = this.ip2dec(ip);
	}
	if (typeof mask != "number") {
		try {
			mask = this.mask2bits(mask);
		} catch (e) {
			if (typeof e == "string") e = "getNetDec(" + [].slice.call(arguments).join(',') + "): " + e;
			throw e;
		}
	}
	if (typeof ip != "number") throw "getNetDec(" + [].slice.call(arguments).join(',') + "): IP not set";
	if ( this.maskbits < 0 || this.maskbits > 32) throw "getNet(" + [].slice.call(arguments).join(',') + "): Invalid netmask" + mask;
	try {
		return this.and(ip,this.mask2dec(mask));
	} catch (e) {
		if (typeof e == "string") e = "getNetDec(" + [].slice.call(arguments).join(',') + "): " + e;
		throw e;
	}
}

JsSubnet.prototype.getNet = function (ip,mask)
{
	try {
		var net =  this.dec2ip(this.getNetDec(ip,mask));
		if (ip == undefined && mask == undefined) this.network = net;
		return net;
	} catch (e) {
		if (typeof e == "string") e = "getNet(" + [].slice.call(arguments).join(',') + "): " + e;
		throw e;
	}
}

JsSubnet.prototype.getIP = function ()
{
	try {
		var ipstr = this.getVal('ip');
		var ipmat,ip,mask;
		if (ipmat = ipstr.match(/^[ ]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[ \/]*$/)) {
			/* IP address only */
			ip = ipmat[1];
			mask = undefined;
		} else if (ipmat = ipstr.match(/^[ ]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[ \/]([0-9]{1,2})[ ]*$/))
		{
			/* CIDR notation */
			ip = ipmat[1];
			mask = ipmat[2];
		} else if (ipmat = ipstr.match(/^[ ]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[ \/]([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})[ ]*$/))
		{
			/* IP address/Mask */
			ip = ipmat[1];
			mask = this.mask2bits(ipmat.slice(2).join('.'));

		}

		if (ip) {
			this.ipaddress = ip;
		}

		if (mask == undefined) {
			this.maskbits = parseInt(this.getVal('mask'));
		} else {
			this.maskbits = parseInt(mask);
		}
		return ip;
	} catch (e) {
		if (typeof e == "string") e = "getIP(" + [].slice.call(arguments).join(',') + "): " + e;
		throw e;
	}
}

JsSubnet.prototype.getBroadcastDec = function (netip,netmask)
{
	if (netmask == undefined) netmask = this.maskbits;
	if (netip == undefined) netip = this.ipaddress;
	try {
		if (typeof netip != 'number') netip = this.ip2dec(netip);
		if (typeof netmask != 'number') netmask = this.mask2bits(netmask);
		var bcastdec;
		if (netmask < 32) {
			var hostdec = this.not(this.mask2dec(netmask),32);
			bcastdec = this.or(netip,hostdec);
		}
		return bcastdec;
	} catch (e) {
		if (typeof e == "string") e = "getBroadcastDec(" + [].slice.call(arguments).join(',') + "): " + e;
		throw e;
	}
}

JsSubnet.prototype.getBroadcast = function (netip,netmask)
{
	try {
		var bcastdec = this.getBroadcastDec(netip,netmask);
		var bcast = (bcastdec)?this.dec2ip(bcastdec):"";
		if (netip == undefined && netmask == undefined) this.broadcast = bcast;
		return bcast;
	} catch (e) {
		if (typeof e == "string") e = "getBroadcast(" + [].slice.call(arguments).join(',') + "): " + e;
		throw e;
	}
}

JsSubnet.prototype.getUsable = function (netip,netmask)
{
	if (netip == undefined && netmask == undefined) {
		var netip = this.ipaddress;
		var netmask = this.maskbits;
		var noargs = true;
	}
	try {
		if (typeof netmask != 'number') netmask = this.mask2bits(netmask); 
		var usable,first,last,netdec,hostdec;
		netdec = this.getNetDec(netip,netmask);
		hostdec = this.not(this.mask2dec(netmask));
		if (netmask > 30) {
			usable = 0;
			first = '';
			last = '';
		} else {
			usable = hostdec - 1;
			first = this.dec2ip(netdec + 1);
			last = this.dec2ip(this.getBroadcastDec(netip,netmask) - 1);
		}
		if (noargs === true) {
			this.usable = usable;
			this.ipcount = hostdec + 1;
			this.first = first;
			this.last = last;
		}
		return {usable:usable,first:first,last:last};
	} catch (e) {
		if (typeof e == "string") e = "getUsable(" + [].slice.call(arguments).join(',') + "): " + e;
		throw e;
	}
}

JsSubnet.prototype.getHostBits = function(ip,mxbit) 
{
	var ret = 0;
	if (!mxbit) mxbit=32;
	for(var i = 0; i < mxbit; i++) {
		if ((this.and(ip,Math.pow(2,i) - 1) == 0)) ret = i + 1;
	}
	return ret;
}

JsSubnet.prototype.innerCIDRBuild = function (ip1,ip2,netlist,maxhostbits)
{
	if (ip1 > ip2) return;
	if (ip1 == ip2) {
		netlist.push(this.dec2ip(ip1) + "/32");
	} else {
		var netbits = (32 - this.getHostBits(ip1,maxhostbits));
		var netaddr = this.getNetDec(ip1,netbits);
		var bcast = this.getBroadcastDec(ip1,netbits);
		while (((netaddr < ip1) || (bcast > ip2)) && (netbits < 32)) {
			netbits += 1;
			netaddr = this.getNetDec(ip1,netbits);
			bcast = this.getBroadcastDec(ip1,netbits);
		}
		if (netbits == 32) bcast = ip1;
		netlist.push(this.dec2ip(netaddr) + "/" + netbits);
		this.innerCIDRBuild(bcast + 1, ip2,netlist,maxhostbits);
	}
}

JsSubnet.prototype.getCIDRList = function(ip1,ip2)
{
	var maxhostbits = Math.floor(Math.log(this.xor(ip1,ip2))/Math.log(2)) + 1;
	var netlist = Array();

	this.innerCIDRBuild(ip1,ip2,netlist,maxhostbits);
	return netlist.join(",");
}

JsSubnet.prototype.updateCIDRList = function()
{
	var start = this.getVal('cidrstartip');
	var stop = this.getVal('cidrendip');
	if (start && stop && start.match(/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/) && stop.match(/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/)) {
		this.objlist['cidrlist'].innerHTML = this.getCIDRList(this.ip2dec(this.getVal('cidrstartip')), this.ip2dec(this.getVal('cidrendip'))).replace(/,/g,"\r\n");
		this.objlist['cidrlist'].style.height = (this.objlist['cidrlist'].clientHeight + this.panel.spareHeight()) + 'px';
		this.objlist['cidrlist'].style.width = '100%';
	}
}

JsSubnet.prototype.updateSubnet = function ()
{
	try {
		this.ipaddress = this.getVal('ip');
		this.maskbits = this.getVal('mask');
		this.getIP();
		this.setVal('ip',this.ipaddress);
		this.setVal('mask',this.maskbits);
		this.setVal('bits',this.maskbits);
		this.getNet();
		this.setVal('net',this.network);
		this.getUsable();
		this.setVal('usable',this.usable);
		this.setVal('first',this.first);
		this.setVal('last',this.last);
		this.setVal('ipcount',this.ipcount);
		this.getBroadcast();
		this.setVal('broadcast',this.broadcast);
	} catch (e) {
		if (typeof e == "string") e = "updateSubnet(" + [].slice.call(arguments).join(',') + "): " + e;
		throw e;
	} 
}

JsSubnet.prototype.isHTML = function (obj) 
{
     var res = false;
	if (mat = obj.constructor.toString().match(/HTML([a-zA-Z0-9]*)Element/)) {
		res = mat[1];
	}
	return res;
}

JsSubnet.prototype.makeElement = function (tag, id, cssclass, attrs) {
	var newel = document.createElement(tag);
	newel.id = id;
	if (cssclass != null) newel.className = cssclass;
	if (tag == 'textarea') console.log(attrs);
	if (typeof attrs == "object") {
		for (var key in attrs) {
			newel[key] = attrs[key];
		}
	}
	if (tag == 'textarea') console.log(newel);
	return newel;
}

JsSubnet.prototype.replaceElement = function (objid,obj)
{
	if (this.isHTML(this.objlist[objid])) {
		var pnode = this.objlist[objid].parentNode;
		pnode.removeChild(this.objlist[objid]);
	}                 

}

JsSubnet.prototype.removePanel = function(el)
{
	while (el.childNodes.length > 0) {
		this.removePanel(el.childNodes[0]);
	}
	el.parentNode.removeChild(el);
	if (/JsSubnet/.exec(el.id)) {
	    el = null;
	}
}

JsSubnet.prototype.togglePanel = function (el,cls)
{
	if ('className' in this.panel) {
		var clsregex = new RegExp("(^|\\s)" + cls + "(\\s|$)");
		if (clsregex.exec(this.panel.className)) {
			this.panel.className = this.panel.className.replace(clsregex,"");
			if(el) el.innerHTML = "-";
		} else {
			this.panel.className = this.panel.className + " " + cls;
			if (el) el.innerHTML = "+";
		}	
	}
}

JsSubnet.prototype.buildSubnetPanel = function(options)
{
	if (this.objlist['ip'] == null || this.objlist['mask'] == null) {
		var inputs = this.makeElement('div','JsSubnet_inputs','JsSubnet');

		if (this.objlist['ip'] == null) {
			var dv = this.makeElement('div','JsSubnet_output_ip_lbl','JsSubnet JsSubnet_label',{innerHTML:this.objlabels['ip'] } );
			this.objlist['ip'] = this.makeElement('input','JsSubnet_input_ip','JsSubnet',{type:'text',maxlength:19});
			dv.appendChild(this.objlist['ip']);
			inputs.appendChild(dv);
		}
		if (this.objlist['mask'] == null) {
			var dv = this.makeElement('div','JsSubnet_output_mask_lbl','JsSubnet JsSubnet_label',{innerHTML:this.objlabels['mask'] } );
			this.objlist['mask'] = this.makeElement('select','JsSubnet_input_mask','JsSubnet');
			for (var i=32; i>=0; i--) { 
				var maskopt = this.makeElement('option','JsSubnet_input_mask_' + i,'JsSubnet',{value:i,innerHTML:this.dec2ip(this.mask2dec(i))});
				this.objlist['mask'].appendChild(maskopt);
			}
			dv.appendChild(this.objlist['mask']);
			inputs.appendChild(dv); 
		}
		this.panel.appendChild(inputs);
	}
	var thisinst = this;
	if (this.isHTML(this.objlist['ip'])) this.panel._addEventListener(this.objlist['ip'],'change',function() {thisinst.updateSubnet();});
	if (this.isHTML(this.objlist['mask'])) this.panel._addEventListener(this.objlist['mask'],'change',function() {thisinst.updateSubnet();});

	var outputs = this.makeElement('div','JsSubnet_outputs','JsSubnet');

	for (var item in this.objlist) {
		if (!item.match(/^ip$|^mask$|^cidr/) && this.objlist[item] == null) {
			if (this.isHTML(this.objlist[item] = this.makeElement('span','JsSubnet_output_'+item,'JsSubnet'))) {
				var dv = this.makeElement('div','JsSubnet_output_' + item + '_lbl','JsSubnet JsSubnet_label',{innerHTML:this.objlabels[item] } );
				dv.appendChild(this.objlist[item]);
				outputs.appendChild(dv);
			}
		}
	}
	this.panel.appendChild(outputs);
}

JsSubnet.prototype.buildCIDRPanel = function(options)
{
	if (this.objlist['cidrstartip'] == null) {
		var dv = this.makeElement('div','JsSubnet_input_ip1_lbl','JsSubnet JsSubnet_cidr_label',{innerHTML:this.objlabels['cidrstartip'] } );
		this.objlist['cidrstartip'] = this.makeElement('input','JsSubnet_input_ip1','JsSubnet',{type:'text',maxlength:19});
		dv.appendChild(this.objlist['cidrstartip']);
		this.panel.appendChild(dv);
	}
	if (this.objlist['cidrendip'] == null) {
		var dv = this.makeElement('div','JsSubnet_input_ip2_lbl','JsSubnet JsSubnet_cidr_label',{innerHTML:this.objlabels['cidrendip'] } );
		this.objlist['cidrendip'] = this.makeElement('input','JsSubnet_input_ip2','JsSubnet',{type:'text',maxlength:19});
		dv.appendChild(this.objlist['cidrendip']);
		this.panel.appendChild(dv);
	}
	if (this.objlist['cidrlist'] == null) {
		var dv = this.makeElement('div','JsSubnet_output_lbl','JsSubnet JsSubnet_cidr_label',{innerHTML:this.objlabels['cidrlist'] } );
		var pr = document.createElement('pre');
		this.objlist['cidrlist'] = this.makeElement('textarea','JsSubnet_input_cidrlist','JsSubnet',{readOnly: 'readonly',junk:'test'});
		pr.appendChild(this.objlist['cidrlist']);
		dv.appendChild(pr);
		this.panel.appendChild(dv);
	}
	var thisinst = this;
	if (this.isHTML(this.objlist['cidrstartip'])) this.panel._addEventListener(this.objlist['cidrstartip'],'change',function() {thisinst.updateCIDRList();});
	if (this.isHTML(this.objlist['cidrendip'])) this.panel._addEventListener(this.objlist['cidrendip'],'change',function() {thisinst.updateCIDRList();});
}

JsSubnet.prototype.buildPanel = function (options)
{    
	if (!options) options = {};
	if (this.panel == null) {
		this.panel = new JsPanel(this.options);

		this.panel.buildPanel(options['left'], options['top'], options['height'], options['width']);
		if (options['type'] == 'CIDR') {
			this.buildCIDRPanel(options);
		} else {
			this.buildSubnetPanel(options);
		}
	}
}

JsSubnet.prototype.ready = function()
{
	return (typeof JsPanel == "function");
}

//IE doesn't support __noSuchMethod__ so one at a time
JsSubnet.prototype.getUnique = function() { return this.panel.getUnique.apply(this.panel,arguments); }
JsSubnet.prototype.resize = function() { return this.panel.resize.apply(this.panel,arguments); }
JsSubnet.prototype.minimize = function() { return this.panel.minimize.apply(this.panel,arguments); }
JsSubnet.prototype.maximize = function() { return this.panel.maximize.apply(this.panel,arguments); }
JsSubnet.prototype.moveBy = function() { return this.panel.moveBy.apply(this.panel,arguments); }
JsSubnet.prototype._addElement = function() { return this.panel._addElement.apply(this.panel,arguments); }
JsSubnet.prototype.addElement = function() { return this.panel.addElement.apply(this.panel,arguments); }
JsSubnet.prototype.appendChild = function() { return this.panel.appendChild.apply(this.panel,arguments); }
JsSubnet.prototype.removeLink = function() { return this.panel.removeLink.apply(this.panel,arguments); }
JsSubnet.prototype.setTheme = function() { return this.panel.setTheme.apply(this.panel,arguments); }
JsSubnet.prototype.setTitle = function() { return this.panel.setTitle.apply(this.panel,arguments); }
JsSubnet.prototype.show = function() { return this.panel.show.apply(this.panel,arguments); }
JsSubnet.prototype.hide = function() { return this.panel.hide.apply(this.panel,arguments); }
//pass through any other functions for convenience, if it exists in the panel
//
//JsSubnet.prototype.__noSuchMethod__ = function(fname,args)
//{
//	if (typeof this.panel[fname] !== "function") throw "NoMethodError: "+fname+" is not defined." 
//	return this.panel[fname].apply(this.panel,args);
//}
