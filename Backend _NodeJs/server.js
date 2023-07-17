"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const http = require("http");
const process_1 = require("process");
const fs = require('fs');
const path = require('path');
const { parse } = require('querystring');
const sql = require('mssql');
const crypto = require("crypto");
const config = {
    server: 'localhost',
    database: 'Users',
    user: 'NJSU',
    password: 'NJSQ',
    options: {
        trustServerCertificate: true, // Trust the self-signed certificate
    }
};
var IpToPrint = '0.0.0.0';
const port = process.env.port || 80;
function HashPassword(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
}
sql.connect(config).then(() => {
    console.log('Sql Connection to server: ' + config.server + ' successful\nConnection To DB: ' + config.database + ' Successfull\n');
}).catch((err) => {
    console.error('Error connecting to the database:', err);
    (0, process_1.exit)();
});
function RunSqlQuery(SqlRequest, Query) {
    return new Promise((resolve, reject) => {
        SqlRequest.query(Query, function (Err, Result) {
            if (Err) {
                console.log(Err);
                resolve('Not Found');
            }
            else {
                resolve(Result);
            }
        });
    });
}
function FindUserExists(Username) {
    return __awaiter(this, void 0, void 0, function* () {
        const Query = 'SELECT Id FROM Users WHERE Username = @username';
        const SqlReq = new sql.Request();
        SqlReq.input('username', sql.NVarChar(sql.MAX), Username);
        //console.log('Running the Query: ' + Query);
        const Res = yield RunSqlQuery(SqlReq, Query);
        //console.log(Res);
        //console.log(Res.recordset.length);
        if (!Array.isArray(Res.recordset) || Res.recordset.length <= 0) {
            //console.log('No Match!');
            return false;
        }
        return true;
    });
}
function QueryUserPriv(Username) {
    return __awaiter(this, void 0, void 0, function* () {
        const Query = 'SELECT Privilege FROM Users WHERE Username = @username';
        const SqlReq = new sql.Request();
        SqlReq.input('username', sql.NVarChar(sql.MAX), Username);
        //console.log('Running the Query: ' + Query);
        const Res = yield RunSqlQuery(SqlReq, Query);
        console.log(Res);
        console.log(Res.recordset.length);
        if (!Array.isArray(Res.recordset) || Res.recordset.length <= 0) {
            console.log('No Match!');
            return -1;
        }
        console.log('User Priv:', Res.recordset[0].Privilege);
        return Res.recordset[0].Privilege;
    });
}
function CheckCredentials(Username, Password) {
    return __awaiter(this, void 0, void 0, function* () {
        const Query = 'SELECT Id FROM Users WHERE Username = @username';
        const Query2 = 'SELECT Id FROM Users WHERE Password = @password';
        const SqlReq = new sql.Request();
        SqlReq.input('username', sql.NVarChar(sql.MAX), Username);
        const SqlReq2 = new sql.Request();
        SqlReq2.input('password', sql.NVarChar(sql.MAX), Password);
        //console.log('Running the Query: ' + Query);
        const Res = yield RunSqlQuery(SqlReq, Query);
        if (!Array.isArray(Res.recordset) || Res.recordset.length <= 0) {
            //console.log('No Match!');
            return false;
        }
        //console.log(Res);
        const ID1 = Res.recordset.Id;
        const Res2 = yield RunSqlQuery(SqlReq2, Query2);
        if (!Array.isArray(Res2.recordset) || Res2.recordset.length <= 0) {
            //console.log('No Match!');
            return false;
        }
        //console.log(Res2);
        const ID2 = Res.recordset.Id;
        if (ID1 == ID2) {
            return true;
        }
        return false;
    });
}
function CreateUser(Username, Password) {
    return __awaiter(this, void 0, void 0, function* () {
        const Query = 'INSERT INTO Users (Username, Password, Privilege) VALUES(@username, @password, @Priv);';
        const SqlReq = new sql.Request();
        SqlReq.input('username', sql.NVarChar(sql.MAX), Username);
        SqlReq.input('password', sql.NVarChar(sql.MAX), Password);
        SqlReq.input('Priv', sql.SmallInt, 0);
        //console.log('Running the Query: ' + Query);
        const Res = yield RunSqlQuery(SqlReq, Query);
        console.log(Res);
        //console.log(Res.recordset.length);
    });
}
function BuildHtml(Url) {
    return __awaiter(this, void 0, void 0, function* () {
        if (Url === '/') {
            const Fn = path.join(__dirname, 'index.html');
            try {
                const Data = yield fs.promises.readFile(Fn, 'utf8');
                return Data;
            }
            catch (Err) {
                console.error('Error reading file: ', Err);
                return 'Error';
            }
        }
        if (Url == '/CreateAccount') {
            const Fn = path.join(__dirname, 'CreateAccount.html');
            try {
                const Data = yield fs.promises.readFile(Fn, 'utf8');
                return Data;
            }
            catch (Err) {
                console.error('Error reading file: ', Err);
                return 'Error';
            }
        }
        if (Url == '/CreateAccountErrorUser') {
            const Fn = path.join(__dirname, 'CreateAccountErrorUser.html');
            try {
                const Data = yield fs.promises.readFile(Fn, 'utf8');
                return Data;
            }
            catch (Err) {
                console.error('Error reading file: ', Err);
                return 'Error';
            }
        }
        if (Url == '/CreateAccountErrorPass') {
            const Fn = path.join(__dirname, 'CreateAccountErrorPassword.html');
            try {
                const Data = yield fs.promises.readFile(Fn, 'utf8');
                return Data;
            }
            catch (Err) {
                console.error('Error reading file: ', Err);
                return 'Error';
            }
        }
        if (Url == '/Login') {
            const Fn = path.join(__dirname, 'Login.html');
            try {
                const Data = yield fs.promises.readFile(Fn, 'utf8');
                return Data;
            }
            catch (Err) {
                console.error('Error reading file: ', Err);
                return 'Error';
            }
        }
        if (Url == '/LoginError') {
            const Fn = path.join(__dirname, 'LoginError.html');
            try {
                const Data = yield fs.promises.readFile(Fn, 'utf8');
                return Data;
            }
            catch (Err) {
                console.error('Error reading file: ', Err);
                return 'Error';
            }
        }
        if (Url == '/AdminPanel') {
            var Head = '';
            var Body = '<form action="/Login" method="POST" enctype="application/x-www-form-urlencoded" target="_self"> <label for="UNAME"> Username </label> <br> <input type="text" id="UNAME" name="UNAME"> <br> <label for="PASSWORD"> Password </label> <br> <input type="password" id="PASSWORD" name="PASSWORD"> <br><br> <input type="submit" value="Login" > </form>';
            var Css = 'body { background-color: black; color: #39FF14; } a:visited, a:link { color: #39FF14 }';
            return '<style>' + Css + '</style>' + '<!DOCTYPE html>' + '<html><head>' + Head + '</head><body>' + Body + '</body></html>';
        }
    });
}
function ParsePOST(Request, Cb) {
    var Body = '';
    Request.on('data', Chunk => {
        Body += Chunk.toString();
    });
    Request.on('end', () => {
        console.log(Body);
        Cb(parse(Body));
    });
}
http.createServer(function (Req, Res) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('Request Recieved');
        console.log('Http Version: ' + Req.httpVersion);
        console.log('Status Code: ' + Req.statusCode);
        console.log('Request IP: ' + Req.socket.remoteAddress);
        console.log('Request URL: ' + Req.url);
        console.log('Request Method: ' + Req.method);
        if (Req.url == '/') {
            IpToPrint = Req.socket.remoteAddress;
            var HtmlToWrite = yield BuildHtml(Req.url);
            Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
            Res.end(HtmlToWrite);
        }
        else if (Req.url == '/CreateAccount') {
            if (Req.method == 'GET') {
                var HtmlToWrite = yield BuildHtml(Req.url);
                Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                Res.end(HtmlToWrite);
            }
            if (Req.method == 'POST') {
                ParsePOST(Req, (Parsed) => __awaiter(this, void 0, void 0, function* () {
                    if (Parsed.PASSWORD != Parsed.PASSWORD2) {
                        var HtmlToWrite = yield BuildHtml(Req.url + 'ErrorPass');
                        Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                        Res.end(HtmlToWrite);
                    }
                    else {
                        FindUserExists(Parsed.UNAME).then((UserExists) => __awaiter(this, void 0, void 0, function* () {
                            if (!UserExists) {
                                yield CreateUser(Parsed.UNAME, Parsed.PASSWORD);
                                Res.writeHead(302, { 'Location': '/Login' });
                                Res.end();
                            }
                            else {
                                var HtmlToWrite = yield BuildHtml(Req.url + 'ErrorUser');
                                Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                                Res.end(HtmlToWrite);
                            }
                        }));
                    }
                }));
            }
        }
        else if (Req.url == '/Login') {
            if (Req.method == 'GET') {
                var HtmlToWrite = yield BuildHtml(Req.url);
                Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                Res.end(HtmlToWrite);
            }
            else if (Req.method == 'POST') {
                ParsePOST(Req, Parsed => {
                    console.log('POST RESULT: Uname: ' + Parsed.UNAME + ' Password: ' + Parsed.PASSWORD);
                    FindUserExists(Parsed.UNAME).then((UserExists) => __awaiter(this, void 0, void 0, function* () {
                        if (!UserExists) {
                            var HtmlToWrite = yield BuildHtml(Req.url + 'Error');
                            Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                            Res.end(HtmlToWrite);
                        }
                        else {
                            CheckCredentials(Parsed.UNAME, Parsed.PASSWORD).then((CredentialsMatch) => __awaiter(this, void 0, void 0, function* () {
                                if (CredentialsMatch) {
                                    const Head = '<p>Credentials Match</p>';
                                    const Body = '';
                                    const Css = 'body { background-color: black; color: #39FF14; } a:visited, a:link { color: #39FF14 }';
                                    var Script = '';
                                    QueryUserPriv(Parsed.UNAME).then((PrivVal) => {
                                        if (PrivVal >= 10) {
                                            console.log('User is Admin: ', PrivVal.toString());
                                            Script = '<script>const form = document.createElement(\'form\'); form.method = \'POST\'; form.action = \'/AdminPanel\'; const unameInput = document.createElement(\'input\'); unameInput.type = \'hidden\'; unameInput.name = \'UNAME\'; unameInput.value = \'' + Parsed.UNAME + '\'; form.appendChild(unameInput); const passwordInput = document.createElement(\'input\'); passwordInput.type = \'hidden\'; passwordInput.name = \'PASSWORD\'; passwordInput.value = \'' + Parsed.PASSWORD + '\'; form.appendChild(passwordInput); document.body.appendChild(form); form.submit(); </script>';
                                            Res.writeHead(200, { 'Content-Type': 'text/html' });
                                            Res.end('<style>' + Css + '</style>' + '<!DOCTYPE html>' + '<html><head>' + Head + '</head><body>' + Script + Body + '</body></html>');
                                        }
                                        else {
                                            console.log('User is Member: ' + PrivVal);
                                            Script = '<script>const form = document.createElement(\'form\'); form.method = \'POST\'; form.action = \'/User\'; const unameInput = document.createElement(\'input\'); unameInput.type = \'hidden\'; unameInput.name = \'UNAME\'; unameInput.value = \'' + Parsed.UNAME + '\'; form.appendChild(unameInput); const passwordInput = document.createElement(\'input\'); passwordInput.type = \'hidden\'; passwordInput.name = \'PASSWORD\'; passwordInput.value = \'' + Parsed.PASSWORD + '\'; form.appendChild(passwordInput); document.body.appendChild(form); form.submit(); </script>';
                                            Res.writeHead(200, { 'Content-Type': 'text/html' });
                                            Res.end('<style>' + Css + '</style>' + '<!DOCTYPE html>' + '<html><head>' + Head + '</head><body>' + Script + Body + '</body></html>');
                                        }
                                    });
                                }
                                else {
                                    var HtmlToWrite = yield BuildHtml(Req.url + 'Error');
                                    Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                                    Res.end(HtmlToWrite);
                                }
                            }));
                        }
                    }));
                });
            }
        }
        else if (Req.url == '/User') {
            if (Req.method == 'GET') {
                Res.writeHead(302, { 'Location': '/Login' });
                Res.end();
            }
            else if (Req.method == 'POST') {
                ParsePOST(Req, Parsed => {
                    var Head = '<p>Welcome: ' + Parsed.UNAME + '</p>';
                    var Body = '';
                    var Css = 'body { background-color: black; color: #39FF14; } a:visited, a:link { color: #39FF14 }';
                    Res.writeHead(200, { 'Content-Type': 'text/html' });
                    Res.end('<style>' + Css + '</style>' + '<!DOCTYPE html>' + '<html><head>' + Head + '</head><body>' + Body + '</body></html>');
                });
            }
        }
        else if (Req.url == '/AdminPanel') {
            if (Req.method == 'GET') {
                Res.writeHead(302, { 'Location': '/Login' });
                Res.end();
            }
            else if (Req.method == 'POST') {
                ParsePOST(Req, Parsed => {
                    CheckCredentials(Parsed.UNAME, Parsed.PASSWORD).then((CredentialsMatch) => {
                        if (CredentialsMatch) {
                            QueryUserPriv(Parsed.UNAME).then((PrivVal) => {
                                var Head = '<p>Welcome Admin: ' + Parsed.UNAME + '</p>';
                                var Body = '';
                                var Css = 'body { background-color: black; color: #39FF14; } a:visited, a:link { color: #39FF14 }';
                                Res.writeHead(200, { 'Content-Type': 'text/html' });
                                Res.end('<style>' + Css + '</style>' + '<!DOCTYPE html>' + '<html><head>' + Head + '</head><body>' + Body + '</body></html>');
                            });
                        }
                        else {
                            var Head = '<p>ERROR!</p>';
                            var Body = '';
                            var Css = 'body { background-color: black; color: #39FF14; } a:visited, a:link { color: #39FF14 }';
                            Res.writeHead(200, { 'Content-Type': 'text/html' });
                            Res.end('<style>' + Css + '</style>' + '<!DOCTYPE html>' + '<html><head>' + Head + '</head><body>' + Body + '</body></html>');
                        }
                    });
                });
            }
        }
        else if (Req.url == '/User/Api') {
        }
        else {
            console.log('Http repsonse is 404');
            Res.statusCode = 404;
            Res.end();
        }
        console.log('\n');
    });
}).listen(port);
//# sourceMappingURL=server.js.map