'use strict';
'require baseclass';

/* Exact registrant aliases verified against Wireshark's IEEE export, 2026-11-05.
 * Normalize typography and legal suffixes only; never infer a device brand from
 * a substring, an acquisition, a joint venture or an unrelated subsidiary.
 * Source: https://www.wireshark.org/download/automated/data/manuf
 * Add aliases only after verifying the registrant and its established Chinese name. */
function normalize(value) {
	if (typeof value !== 'string') return '';
	var name = value.toLowerCase().replace(/[.,'’"()&_-]+/g, ' ').replace(/\s+/g, ' ').trim();
	var previous;
	do {
		previous = name;
		name = name.replace(/(?:^| )(?:co|company|corp|corporation|inc|incorporated|ltd|limited|llc)$/, '').trim();
	} while (name !== previous);
	return name;
}

var REGISTRANTS = [
	{ key: 'apple', label: '苹果', aliases: [ 'Apple' ] },
	{ key: 'asus', label: '华硕', aliases: [ 'ASUSTek COMPUTER', 'ASUS' ] },
	{ key: 'xiaomi', label: '小米', aliases: [ 'Xiaomi Communications', 'Xiaomi Electronics', 'Beijing Xiaomi Electronics', 'Beijing Xiaomi Mobile Software' ] },
	{ key: 'samsung', label: '三星', aliases: [ 'Samsung Electronics', 'Samsung Semiconductor', 'Samsung Electro Mechanics' ] },
	{ key: 'intel', label: '英特尔', aliases: [ 'Intel', 'Intel Corporate', 'Intel Wireless Network Group' ] },
	{ key: 'huawei', label: '华为', aliases: [ 'Huawei Technologies', 'Huawei Device' ] },
	{ key: 'mediatek', label: '联发科', aliases: [ 'MediaTek' ] },
	{ key: 'qualcomm', label: '高通', aliases: [ 'Qualcomm' ] },
	{ key: 'tplink', label: '普联', aliases: [ 'TP Link Technologies', 'TP Link Systems', 'TPLink Technologies' ] },
	{ key: 'hp', label: '惠普', aliases: [ 'Hewlett Packard', 'HP' ] },
	{ key: 'dell', label: '戴尔', aliases: [ 'Dell', 'Dell EMC', 'Dell Technologies' ] },
	{ key: 'lenovo', label: '联想', aliases: [ 'Lenovo', 'Lenovo (Beijing)', 'Lenovo Mobile Communication Technology', 'Lenovo Mobile Communication (Wuhan)' ] },
	{ key: 'sony', label: '索尼', aliases: [ 'Sony', 'Sony Interactive Entertainment', 'Sony Visual Products', 'Sony Video & Sound Products' ] },
	{ key: 'cisco', label: '思科', aliases: [ 'Cisco Systems', 'Cisco Systems Norway', 'Cisco Meraki', 'Cisco SPVTG' ] },
	{ key: 'realtek', label: '瑞昱', aliases: [ 'Realtek Semiconductor' ] },
	{ key: 'broadcom', label: '博通', aliases: [ 'Broadcom', 'Broadcom Technologies' ] },
	{ key: 'google', label: '谷歌', aliases: [ 'Google' ] },
	{ key: 'honor', label: '荣耀', aliases: [ 'Honor Device' ] },
	{ key: 'meizu', label: '魅族', aliases: [ 'Meizu Technology' ] },
	{ key: 'synology', label: '群晖', aliases: [ 'Synology' ] },
	{ key: 'qnap', label: '威联通', aliases: [ 'QNAP Systems' ] },
	{ key: 'espressif', label: '乐鑫', aliases: [ 'Espressif', 'Espressif Systems (Shanghai)' ] },
	{ key: 'nvidia', label: '英伟达', aliases: [ 'NVIDIA' ] },
	{ key: 'amd', label: '超威', aliases: [ 'Advanced Micro Devices' ] },
	{ key: 'nokia', label: '诺基亚', aliases: [ 'Nokia', 'Nokia Solutions and Networks' ] },
	{ key: 'netgear', label: '网件', aliases: [ 'NETGEAR' ] },
	{ key: 'amazon', label: '亚马逊', aliases: [ 'Amazon Technologies', 'Amazon.com' ] },
	{ key: 'lg', label: 'LG电子', aliases: [ 'LG Electronics', 'LG Electronics (Mobile Communications)' ] },
	{ key: 'microsoft', label: '微软', aliases: [ 'Microsoft', 'Microsoft Research', 'Microsoft XCG' ] },
	{ key: 'nintendo', label: '任天堂', aliases: [ 'Nintendo' ] },
	{ key: 'oppo', label: 'OPPO', aliases: [ 'Guangdong OPPO Mobile Telecommunications' ] },
	{ key: 'vivo', label: 'vivo', aliases: [ 'vivo Mobile Communication' ] },
	{ key: 'oneplus', label: '一加', aliases: [ 'OnePlus Electronics (Shenzhen)', 'OnePlus Tech (Shenzhen)', 'OnePlus Technology (Shenzhen)' ] },
	{ key: 'realme', label: 'realme', aliases: [ 'Realme Chongqing Mobile Telecommunications', 'Realme Chongqing MobileTelecommunications' ] },
	{ key: 'motorola', label: '摩托罗拉', aliases: [ 'Motorola', 'Motorola Solutions', 'Motorola (Wuhan) Mobility Technologies Communication' ] },
	{ key: 'acer', label: '宏碁', aliases: [ 'Acer', 'Acer Computer(Shanghai)' ] },
	{ key: 'msi', label: '微星', aliases: [ "Micro-Star INT'L", 'Micro-Star INTL', 'Micro-Star International' ] },
	{ key: 'gigabyte', label: '技嘉', aliases: [ 'GIGA-BYTE TECHNOLOGY' ] },
	{ key: 'midea', label: '美的', aliases: [ 'Midea Group' ] },
	{ key: 'tuya', label: '涂鸦智能', aliases: [ 'Tuya Smart' ] },
	{ key: 'aqara', label: '绿米科技', aliases: [ 'Lumi United Technology' ] },
	{ key: 'hikvision', label: '海康威视', aliases: [ 'Hangzhou Hikvision Digital Technology' ] },
	{ key: 'dahua', label: '大华', aliases: [ 'Zhejiang Dahua Technology' ] },
	{ key: 'brother', label: '兄弟', aliases: [ 'Brother Industries' ] },
	{ key: 'raspberrypi', label: '树莓派', aliases: [ 'Raspberry Pi (Trading)', 'Raspberry Pi Trading', 'Raspberry Pi Foundation' ] },
	{ key: 'dlink', label: '友讯', aliases: [ 'D-Link', 'D-Link International', 'D-Link (Shanghai)' ] },
	{ key: 'ubiquiti', label: 'Ubiquiti', aliases: [ 'Ubiquiti' ] },
	{ key: 'epson', label: '爱普生', aliases: [ 'Seiko Epson' ] },
	{ key: 'canon', label: '佳能', aliases: [ 'Canon', 'Canon Imaging Systems', 'Canon Korea' ] },
	{ key: 'sharp', label: '夏普', aliases: [ 'SHARP' ] },
	{ key: 'hisense', label: '海信', aliases: [ 'Hisense Electric', 'Hisense Mobile Communications Technoligy', 'Hisense Broadband Multimedia Technology' ] }
];
var aliases = Object.create(null);
REGISTRANTS.forEach(function(entry) {
	entry.aliases.forEach(function(alias) { aliases[normalize(alias)] = entry; });
});

function resolve(name) {
	var entry = aliases[normalize(name)];
	return entry ? { key: entry.key, label: entry.label } : null;
}

return baseclass.extend({ resolve: resolve, normalize: normalize });
