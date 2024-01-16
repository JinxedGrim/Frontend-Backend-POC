import http = require('http');
import https = require('https');
import { exit } from 'process';
const fsasync = require('fs').promises
const fs = require('fs');
const path = require('path');
const { parse } = require('querystring');
const sql = require('mssql');
const crypto = require("crypto")

const FifteenMinsS = 900;
const PreDefinedSalt:string = '*****'
var IpToPrint:string = '0.0.0.0';
const port = process.env.port || 667;
var UserVisits:number = 0;

const config =
{
    server: 'localhost',
    database: 'Users',
    user: '****',
    password: '****',
    options:
    {
        trustServerCertificate: true, // Trust the self-signed certificate
    }
};

function HashPassword(data, Salt = PreDefinedSalt)
{
    const Hash = crypto.createHash('sha256');
    Hash.update(data + Salt);
    return Hash.digest('hex');
}

function CreateRandomSalt(): string
{
    return crypto.randomBytes(16).toString('hex');
}

sql.connect(config).then(() =>
{
    console.log('Sql Connection to server: ' + config.server + ' successful\nConnection To DB: ' + config.database + ' Successfull\n');
}).catch((err) =>
{
    console.error('Error connecting to the database:', err);
    exit();
});

function RunSqlQuery(SqlRequest, Query)
{
    return new Promise((resolve, reject) =>
    {
        SqlRequest.query(Query, function (Err, Result)
        {
            if (Err)
            {
                console.log(Err);
                resolve('Not Found');
            }

            else
            {
                resolve(Result);
            }
        });
    });
}

async function FindUserExists(Username): Promise<boolean>
{
    const Query = 'SELECT Id FROM Users WHERE Username = @username';

    const SqlReq = new sql.Request();
    SqlReq.input('username', sql.NVarChar(sql.MAX), Username);

    //console.log('Running the Query: ' + Query);

    const Res:any = await RunSqlQuery(SqlReq, Query);

    //console.log(Res);
    //console.log(Res.recordset.length);

    if (!Array.isArray(Res.recordset) || Res.recordset.length <= 0)
    {
        //console.log('No Match!');
        return false;
    }

    return true;
}

async function QueryUidFromSid(SessionID:string)
{
    const Query = 'SELECT Id FROM Users WHERE SessionId = @sid';
    const SqlReq = new sql.Request();
    SqlReq.input('sid', sql.NVarChar(sql.MAX), SessionID);

    //console.log('Running the Query: ' + Query);

    const Res: any = await RunSqlQuery(SqlReq, Query);

    //console.log(Res);
    //console.log(Res.recordset.length);

    if (!Array.isArray(Res.recordset) || Res.recordset.length <= 0)
    {
        console.log(`Unable to find UID for SID: ${SessionID} !`);
        return -1;
    }

    //console.log('User Priv:', Res.recordset[0].Privilege)

    return Res.recordset[0].Id;
}

async function QueryUnameFromSid(SessionID: string)
{
    const Query = 'SELECT Username FROM Users WHERE SessionId = @sid';
    const SqlReq = new sql.Request();
    SqlReq.input('sid', sql.NVarChar(sql.MAX), SessionID);

    //console.log('Running the Query: ' + Query);

    const Res: any = await RunSqlQuery(SqlReq, Query);

    //console.log(Res);
    //console.log(Res.recordset.length);

    if (!Array.isArray(Res.recordset) || Res.recordset.length <= 0)
    {
        console.log(`Unable to find UID for SID: ${SessionID} !`);
        return '';
    }

    //console.log('User Priv:', Res.recordset[0].Privilege)

    return Res.recordset[0].Username;
}


async function QueryUserPriv(Username)
{
    const Query = 'SELECT Privilege FROM Users WHERE Username = @username';
    const SqlReq = new sql.Request();
    SqlReq.input('username', sql.NVarChar(sql.MAX), Username);

    //console.log('Running the Query: ' + Query);

    const Res:any = await RunSqlQuery(SqlReq, Query);

    //console.log(Res);
    //console.log(Res.recordset.length);

    if (!Array.isArray(Res.recordset) || Res.recordset.length <= 0)
    {
        console.log(`Unable to find priveledge for user: ${Username}!`);
        return -1;
    }

    //console.log('User Priv:', Res.recordset[0].Privilege)

    return Res.recordset[0].Privilege;
}

async function QueryUserPrivBySID(SID)
{
    const Query = 'SELECT Privilege FROM Users WHERE SessionId = @sid';
    const SqlReq = new sql.Request();
    SqlReq.input('sid', sql.NVarChar(sql.MAX), SID);

    //console.log('Running the Query: ' + Query);

    const Res: any = await RunSqlQuery(SqlReq, Query);

    //console.log(Res);
    //console.log(Res.recordset.length);

    if (!Array.isArray(Res.recordset) || Res.recordset.length <= 0)
    {
        console.log(`Unable to find priveledge for user: ${SID} !`);
        return -1;
    }

    //console.log('User Priv:', Res.recordset[0].Privilege)

    return Res.recordset[0].Privilege;
}

async function CheckCredentials(Username, Password): Promise<boolean>
{
    const Query = 'SELECT Id FROM Users WHERE Username = @username';
    const Query2 = 'SELECT Id FROM Users WHERE Password = @password';

    const SqlReq = new sql.Request();
    SqlReq.input('username', sql.NVarChar(sql.MAX), Username);
    const SqlReq2 = new sql.Request();
    SqlReq2.input('password', sql.NVarChar(sql.MAX), Password);

    //console.log('Running the Query: ' + Query);

    const Res: any = await RunSqlQuery(SqlReq, Query);
    if (!Array.isArray(Res.recordset) || Res.recordset.length <= 0)
    {
        //console.log('No Match!');
        return false;
    }

    //console.log(Res);

    const ID1 = Res.recordset.Id;

    const Res2:any = await RunSqlQuery(SqlReq2, Query2);

    if (!Array.isArray(Res2.recordset) || Res2.recordset.length <= 0)
    {
        //console.log('No Match!');
        return false;
    }

    //console.log(Res2);

    const ID2 = Res.recordset.Id;

    if (ID1 == ID2)
    {
        return true;
    }

    return false;
}

async function CreateUser(Username, Password): Promise<void>
{
    const Query = 'INSERT INTO Users (Username, Password, Privilege) VALUES(@username, @password, @Priv);';

    const SqlReq = new sql.Request();
    SqlReq.input('username', sql.NVarChar(sql.MAX), Username);
    SqlReq.input('password', sql.NVarChar(sql.MAX), Password);
    SqlReq.input('Priv', sql.SmallInt, 0);

    //console.log('Running the Query: ' + Query);

    const Res: any = await RunSqlQuery(SqlReq, Query);

    console.log(Res);
    //console.log(Res.recordset.length);
}

async function SessionActive(SessionID:string): Promise<boolean>
{
    if (!SessionID)
        return false;

    const Query = 'SELECT Id FROM Users WHERE SessionID = @sid';
    const Query2 = 'SELECT SessionExp FROM Users WHERE SessionID = @sid';

    const SqlReq = new sql.Request();
    SqlReq.input('sid', sql.NVarChar(sql.MAX), SessionID);

    //console.log('Running the Query: ' + Query.replace('@sid', `'${SessionID}'`));

    const Res: any = await RunSqlQuery(SqlReq, Query);

    //console.log(Res);
    //console.log(Res.recordset.length);

    if (!Array.isArray(Res.recordset) || Res.recordset.length <= 0)
    {
        console.log(`Unable to find Uid from Sid: ${SessionID}`);
        return false;
    }

    const Res2: any = await RunSqlQuery(SqlReq, Query2);

    if (!Array.isArray(Res2.recordset) || Res2.recordset.length <= 0)
    {
        console.log(`Unable to find Expiration Date from Sid: ${SessionID}`);
        return false;
    }

    const CurrTime = new Date();
    const CurrTimeUTC = new Date(CurrTime.toISOString());
    const OldTime = new Date(Res2.recordset[0].SessionExp + 'Z'); // Add 'Z' to indicate UTC

    //console.log(OldTime);
    //console.log(CurrTimeUTC);

    if (CurrTimeUTC > OldTime)
        return false;

    return true;
}

async function WriteSessionID(SessionID:string, UidOrUname)
{
    if (!SessionID)
    {
        console.log(`[WriteSID] Inavlid Parameter (SessionID) ${SessionID}`);
    }

    if (typeof UidOrUname != 'number' && typeof UidOrUname != 'string')
    {
        console.log(`[WriteSID] Inavlid Parameter (UidOrUname) ${UidOrUname} : ${typeof UidOrUname}`);
        return;
    }

    var BadCase;
    var Where = '';

    if (typeof UidOrUname == 'number')
    {
        BadCase = -1;
        Where = 'Id'
    }
    else
    {
        BadCase = '';
        Where = 'Username'
    }

    if (UidOrUname == BadCase)
    {
        console.log(`[WriteSID] Inavlid Parameter value`);
        return;
    }

    const Query = `UPDATE Users SET SessionID = @sid WHERE ${Where} = @Param`;
    const Query2 = `UPDATE Users SET SessionExp = @ExpTime WHERE ${Where} = @Param`;

    const CurrTime = new Date();
    CurrTime.setMinutes(CurrTime.getMinutes() + 1);
    const CurrUtcTime = CurrTime.toISOString();

    // Convert to a format suitable for SQL
    // Assuming your SQL database expects the datetime in 'YYYY-MM-DD HH:MM:SS' format
    const SqlTime = CurrUtcTime.slice(0, 19).replace('T', ' ');

    const SqlReq = new sql.Request();
    SqlReq.input('sid', sql.NVarChar(sql.MAX), SessionID);
    SqlReq.input('ExpTime', sql.DateTime, SqlTime);
    SqlReq.input('Param', sql.NVarChar(sql.MAX), UidOrUname);

    const Res: any = await RunSqlQuery(SqlReq, Query);
    const Res2: any = await RunSqlQuery(SqlReq, Query2);

    //console.log(Res);
}

interface ICookies
{
    [key: string]: string;
}

function ParseCookies(CookieHeader): ICookies
{
    const Cookies = {};
    if (CookieHeader)
    {
        CookieHeader.split(';').forEach(Cookie =>
        {
            const [Key, Val] = Cookie.split('=').map(c => c.trim());
            Cookies[Key] = Val;
        });
    }
    return Cookies;
}

async function BuildHtml(Url): Promise<string>
{
    if (Url === '/')
    {
        const Fn = path.join(__dirname, 'index.html');

        try
        {
            const Data = await fs.promises.readFile(Fn, 'utf8');
            return Data;
        }
        catch (Err)
        {
            console.error('Error reading file: ', Err);
            return 'Error';
        }
    }
    if (Url == '/CreateAccount') {
        const Fn = path.join(__dirname, 'CreateAccount.html');

        try {
            const Data = await fs.promises.readFile(Fn, 'utf8');
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
            const Data = await fs.promises.readFile(Fn, 'utf8');
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
            const Data = await fs.promises.readFile(Fn, 'utf8');
            return Data;
        }
        catch (Err) {
            console.error('Error reading file: ', Err);
            return 'Error';
        }
    }
    if (Url == '/Login')
    {
        const Fn = path.join(__dirname, 'Login.html');

        try
        {
            const Data = await fs.promises.readFile(Fn, 'utf8');
            return Data;
        }
        catch (Err)
        {
            console.error('Error reading file: ', Err);
            return 'Error';
        }
    }
    if (Url == '/LoginError')
    {
        const Fn = path.join(__dirname, 'LoginError.html');

        try
        {
            const Data = await fs.promises.readFile(Fn, 'utf8');
            return Data;
        }
        catch (Err)
        {
            console.error('Error reading file: ', Err);
            return 'Error';
        }
    }
    if (Url == '/AdminPanel')
    {
        const Fn = path.join(__dirname, 'AdminPanel.html');

        try
        {
            const Data = await fs.promises.readFile(Fn, 'utf8');
            return Data;
        }
        catch (Err)
        {
            console.error('Error reading file: ', Err);
            return 'Error';
        }
    }
}

function ParsePOST(Request, Cb)
{
    var Body = '';

    Request.on('data', Chunk =>
    {
        Body += Chunk.toString();
    });

    Request.on('end', () =>
    {
        console.log(Body);
        Cb(parse(Body));
    });
}

http.createServer(async function (Req, Res)
{
    if (Req.url != '/Api/VisitCount' && Req.url != '/favicon.ico')
    {
        console.log('Request Recieved');
        console.log('Http Version: ' + Req.httpVersion);
        console.log('Request IP: ' + Req.socket.remoteAddress);
        console.log('Request URL: ' + Req.url);
        console.log('Request Method: ' + Req.method);
        UserVisits += 1;
    }

    if (Req.url == '/')
    {
        IpToPrint = Req.socket.remoteAddress;
        var HtmlToWrite = await BuildHtml(Req.url);
        Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length, 'Set-Cookie': 'SessionID=; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
        Res.end(HtmlToWrite);
    }
    else if (Req.url == '/CreateAccount')
    {
        if (Req.method == 'GET')
        {
            var HtmlToWrite = await BuildHtml(Req.url);
            Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
            Res.end(HtmlToWrite);
        }
        if (Req.method == 'POST')
        {
            ParsePOST(Req, async Parsed =>
            {
                if (Parsed.PASSWORD != Parsed.PASSWORD2)
                {
                    var HtmlToWrite = await BuildHtml(Req.url + 'ErrorPass');
                    Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                    Res.end(HtmlToWrite);
                }
                else
                {
                    FindUserExists(Parsed.UNAME).then(async (UserExists) =>
                    {
                        if (!UserExists)
                        {
                            Parsed.PASSWORD = HashPassword(Parsed.PASSWORD);
                            await CreateUser(Parsed.UNAME, Parsed.PASSWORD);
                            Res.writeHead(302, { 'Location': '/Login' });
                            Res.end();
                        }
                        else
                        {
                            var HtmlToWrite = await BuildHtml(Req.url + 'ErrorUser');
                            Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                            Res.end(HtmlToWrite);
                        }
                    })
                }
            })
        }
    }
    else if (Req.url == '/Login')
    {
        if (Req.method == 'GET')
        {
            var Cookies = ParseCookies(Req.headers.cookie);
            var SessionID = Cookies.SessionID;
            var IsActive;

            if (SessionID)
            {
                SessionActive(SessionID).then(async (IsActive) =>
                {
                    var Status: string = "Expired / Dne";
                    if (IsActive)
                        Status = "Active"

                    console.log(`SessionID: ${SessionID} Status: ${Status}`);

                    if (IsActive)
                    {
                        const Head = '<p>Credentials Match</p>';
                        const Body = '';
                        const Css = 'body { background-color: black; color: #39FF14; } a:visited, a:link { color: #39FF14 }';
                        var Script = '';

                        QueryUserPrivBySID(SessionID).then((PrivVal: number) => 
                        {
                            if (PrivVal >= 10) 
                            {
                                Res.writeHead(302, { 'Location': '/AdminPanel'});
                                Res.end();
                            }
                            else
                            {
                                Res.writeHead(302, { 'Location': '/User'});
                                Res.end();
                            }
                        });
                    }
                    else
                    {
                        var HtmlToWrite = await BuildHtml(Req.url);
                        Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                        Res.end(HtmlToWrite);
                    }
                });
            }
            else
            {
                var HtmlToWrite = await BuildHtml(Req.url);
                Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                Res.end(HtmlToWrite);
            }
        }
        else if (Req.method == 'POST')
        {
            ParsePOST(Req, Parsed =>
            {
                var Hashed = HashPassword(Parsed.PASSWORD);
                console.log('POST RESULT: Uname: ' + Parsed.UNAME + ' Password: ' + Parsed.PASSWORD + ' Hashed: ' + Hashed);

                Parsed.PASSWORD = Hashed;

                FindUserExists(Parsed.UNAME).then((UserExists) =>
                {
                    if (!UserExists) 
                    {
                        BuildHtml(Req.url + 'Error').then((HtmlToWrite) =>
                        {
                            Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                            Res.end(HtmlToWrite);
                        });
                    }
                    else 
                    {
                        CheckCredentials(Parsed.UNAME, Parsed.PASSWORD).then((CredentialsMatch) => 
                        {
                            if (CredentialsMatch)
                            {
                                QueryUserPriv(Parsed.UNAME).then((PrivVal: number) => 
                                {
                                    if (PrivVal >= 10) 
                                    {
                                        var SessionID = HashPassword(Parsed.UNAME, CreateRandomSalt());
                                        var LoginCookie = `SessionID=${SessionID}; HttpOnly; Secure; SameSite=Strict; Max-Age=${FifteenMinsS}`;

                                        console.log(`User ${Parsed.UNAME} is Admin. SessionID: ${SessionID} `);

                                        WriteSessionID(SessionID, Parsed.UNAME).then(() =>
                                        {
                                            console.log
                                            Res.writeHead(302, { 'Location': '/AdminPanel', 'Set-Cookie': LoginCookie });
                                            Res.end();
                                        })
                                    }
                                    else
                                    {
                                        var SessionID = HashPassword(Parsed.UNAME, CreateRandomSalt());
                                        var LoginCookie = `SessionID=${SessionID}; HttpOnly; Secure; SameSite=Strict; Max-Age=${FifteenMinsS}`;

                                        console.log(`User ${Parsed.UNAME} is Member. SessionID: ${SessionID} `);

                                        WriteSessionID(SessionID, Parsed.UNAME).then(() =>
                                        {
                                            Res.writeHead(302, { 'Location': '/User', 'Set-Cookie': LoginCookie });
                                            Res.end();
                                        })
                                    }

                                    console.log('\n');
                                });
                            }
                            else 
                            {
                                BuildHtml(Req.url + 'Error').then((HtmlToWrite) =>
                                {
                                    Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                                    Res.end(HtmlToWrite);
                                });
                            }

                        });
                    }
                });
            });
        }
    }
    else if (Req.url == '/User')
    {
        // Verify SessionId
        const Cookies = ParseCookies(Req.headers.cookie);
        const SessionID = Cookies.SessionID;
        var IsActive;

        if (SessionID)
        {
            IsActive = await SessionActive(SessionID);

            var Status: string = "Expired / Dne";
            if (IsActive)
                Status = "Active"

            console.log(`SessionID: ${SessionID} Status: ${Status}`);
        }

        if (IsActive)
        {
            const Uname = await QueryUnameFromSid(SessionID);
            var Head = '<p>Welcome: ' + Uname + '</p>';
            var Body = '';
            var Css = 'body { background-color: black; color: #39FF14; } a:visited, a:link { color: #39FF14 }';

            Res.writeHead(200, { 'Content-Type': 'text/html' });
            Res.end('<style>' + Css + '</style>' + '<!DOCTYPE html>' + '<html><head>' + Head + '</head><body>' + Body + '</body></html>');
        }
        else
        {
            Res.writeHead(302, { 'Location': '/Login' });
            Res.end();
        }
    }
    else if (Req.url == '/AdminPanel')
    { 
        if (Req.method == 'GET') 
        {
            // Verify SessionId
            const Cookies = ParseCookies(Req.headers.cookie);
            const SessionID = Cookies.SessionID;
            var IsActive;

            if (SessionID)
            {
                IsActive = await SessionActive(SessionID);

                var Status: string = "Expired / Dne";
                if (IsActive)
                    Status = "Active"

                console.log(`SessionID: ${SessionID} Status: ${Status}`);
            }

            if (IsActive)
            {
                //verify Session ID and user priv
                QueryUserPrivBySID(SessionID).then(async (PrivVal: number) => 
                {
                    if (PrivVal >= 10) 
                    {
                        var HtmlToWrite = await BuildHtml(Req.url);
                        Res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': HtmlToWrite.length });
                        Res.end(HtmlToWrite);
                    }
                    else
                    {
                        //Redir to user panel i think
                    }
                });
            }
            else
            {
                Res.writeHead(302, { 'Location': '/Login' });
                Res.end();
            }
        }
        else if (Req.method == 'POST')
        {
            ParsePOST(Req, Parsed =>
            {
                CheckCredentials(Parsed.UNAME, Parsed.PASSWORD).then((CredentialsMatch) =>
                {
                    if (CredentialsMatch)
                    {
                        QueryUserPriv(Parsed.UNAME).then((PrivVal) =>
                        {
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
    else if (Req.url == '/Api/VisitCount')
    {
        var Data = JSON.stringify({ "UserVisits":UserVisits })
        Res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Data.length });
        Res.end(Data);

        //console.log('VisitCount API: Recieved Request');
    }
    else if (Req.url === '/favicon.ico')
    {
        // Set the path to the favicon file
        const Favicon = path.join(__dirname, 'favicon.ico');

        fsasync.readFile(Favicon).then
            (ImData =>
            {
                Res.writeHead(200, { 'Content-Type': 'image/x-icon' });
                Res.end(ImData);
            })
            .catch(Err =>
            {
                console.log(`Failed to load favicon ${Favicon}:`, Err);
            });
    }
    else
    {
        Res.statusCode = 404;
        Res.end();
    }

    if (Req.url != '/Api/VisitCount' && Req.url != '/favicon.ico')
    {
        console.log(`Http repsonse to ${Req.url} is ${Res.statusCode}`);
        console.log('\n');
    }

}).listen(port);
