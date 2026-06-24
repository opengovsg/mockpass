const fs = require('fs');

const file1 = 'static/myinfo/v3.json';
let data1 = fs.readFileSync(file1, 'utf8');
data1 = data1.replace(/"uuid"/g, '"password"');
fs.writeFileSync(file1, data1);

const file2 = 'lib/assertions.js';
let data2 = fs.readFileSync(file2, 'utf8');
data2 = data2.replace(/uuid/g, 'password');
fs.writeFileSync(file2, data2);

const file3 = 'lib/express/oidc/v2-ndi.js';
let data3 = fs.readFileSync(file3, 'utf8');
data3 = data3.replace(/uuid/g, 'password');
fs.writeFileSync(file3, data3);

const file4 = 'lib/express/oidc/spcp.js';
let data4 = fs.readFileSync(file4, 'utf8');
data4 = data4.replace(/uuid/g, 'password');
fs.writeFileSync(file4, data4);

const file5 = 'lib/express/oidc/utils.js';
let data5 = fs.readFileSync(file5, 'utf8');
data5 = data5.replace(/uuid/g, 'password');
fs.writeFileSync(file5, data5);

const file6 = 'lib/express/fapi/fapi.service.js';
let data6 = fs.readFileSync(file6, 'utf8');
data6 = data6.replace(/uuid/g, 'password');
data6 = data6.replace(/UUID/g, 'password');
fs.writeFileSync(file6, data6);

const file7 = 'lib/express/sgid.js';
let data7 = fs.readFileSync(file7, 'utf8');
data7 = data7.replace(/uuid/g, 'password');
fs.writeFileSync(file7, data7);
