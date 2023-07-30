const fs = require('fs');
const FormData = require('form-data');
const process = require('process');
const readLine = require('readline');
const crypto = require('crypto');
const path = require('path')
const os = require('os')

const COLORS = {
    'BGREEN': '\x1b[1;32;40m',
    'RWHITE': '\x1b[1;37;41m',
    'BBLUE': '\x1b[1;36;40m',
    'BPINK': '\x1b[1;35;40m',
    'BRED': '\x1b[1;31;40m',
    'BYELLOW': '\x1b[1;33;40m',
    'GGREEN': '\x1b[7;37;42m',
    'GBLUE': '\x1b[7;37;46m',
    'BMAGENTA': '\x1b[1;37;46m',
    'END': '\x1b[0m',
    'YELLOW': '\x1b[36m'
}

const CONSTANTS = {
    'STAR': `${COLORS.BGREEN} * ${COLORS.END}`,
    'INFO': `${COLORS.BYELLOW} i ${COLORS.END}`,
    'RATE': `${COLORS.BBLUE} @ ${COLORS.END}`,
    'ASK': `${COLORS.BPINK} ? ${COLORS.END}`,
    'ERROR': `${COLORS.BRED} ! ${COLORS.END}`,
    'AINFO': `${COLORS.BMAGENTA} > ${COLORS.END}`,
    'HDIR': os.homedir(),
    'DIR': path.join(os.homedir(), '.aikit')
}

const SETTINGS = {
    'psid': function () {
        try {
            let content = fs.readFileSync(path.join(CONSTANTS.DIR, 'psid.txt'), { encoding: "utf-8" })
            return content;
        } catch {
            fs.writeFile(path.join(CONSTANTS.DIR, 'psid.txt'), '', () => { })
            return "";
        }
    },
    'hftoken': function () {
        try {
            let content = fs.readFileSync(path.join(CONSTANTS.DIR, 'hftoken.txt'), { encoding: "utf-8" })
            return content;
        } catch {
            fs.writeFile(path.join(CONSTANTS.DIR, 'hftoken.txt'), '', () => { })
            return "";
        }
    }
}

const rl = readLine.createInterface({
    input: process.stdin,
    output: process.stdout
});

function initBard() {
    intro()
    const MESSAGES = {
        "emptyToken": "__Secure-1PSID is not supplied in parameter.",
        "findToken": "You can copy your token from https://bard.google.com -> Dev Console -> Application -> Cookies -> Value of __Secure-1PSID.",
        "findCaptcha": "You can copy your captcha token from https://bard.google.com -> Dev Console -> Application -> Cookies -> Value of GOOGLE_ABUSE_EXEMPTION.",
        "findSnl": "You can manually find SNLM0e token from https://bard.google.com -> View Page Source -> Search for 'SNLM0e'",
        "invalidToken": "Invalid __Secure-1PSID supplied.",
        "googleCaptchaMessage": "Our systems have detected unusual traffic from your computer network.This page checks to see if it's really you sending the requests, and not a robot."
    }

    const URI = {
        "baseURI": "https://bard.google.com/?hl=en",
        "bardURI": "https://bard.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate?bl=boq_assistant-bard-web-server_20230718.13_p2&_reqid=1174904&rt=c"
    }

    let DEBUG = false

    const userAccountsPath = path.join(CONSTANTS.DIR, "accounts.bard")

    function d(functionName, message = "ENTRY") {
        if (DEBUG) {
            console.log(functionName + "(): " + message)
        }
    }

    function createUserAccountsFile(content = "") {
        d("createUserAccountsFile")
        try {
            d("createUserAccountsFile", "Creating file. Given Content: " + content)
            fs.writeFileSync(userAccountsPath, content ? content : content)
        } catch (err) {
            throw err
        }
    }

    function readUserAccounts() {
        d("readUserAccounts")
        if (!fileExists(userAccountsPath)) {
            d("readUserAccounts", "File doesn't exist calling file creator function")
            createUserAccountsFile()
        }
        let content = fs.readFileSync(userAccountsPath, { encoding: "utf8" })
        d("readUserAccounts", "Returned data: " + content)
        return JSON.parse(`{${content}}`)
    }

    function fileExists(filePath) {
        d("fileExists")
        try {
            d("fileExists", "Checking if " + filePath + " exists")
            fs.accessSync(filePath, fs.constants.F_OK)
            d("fileExists", filePath + " exist")
            return true
        } catch {
            d("fileExists", filePath + " doesnt exist")
            return false
        }
    }

    function addAccount(accountDetails) {
        d("addAccount")
        let accounts = readUserAccounts()
        accounts[accountDetails.PSID] = {
            "SNLM0e": accountDetails.SNLM0e,
            "c_id": accountDetails.c_id,
            "r_id": accountDetails.r_id,
            "rc_id": accountDetails.rc_id,
            "captcha": accountDetails.captcha
        }

        accounts = JSON.stringify(accounts).slice(1, -1)

        d("addAccount", "Caling file creater to write " + accounts)

        createUserAccountsFile(accounts)
    }

    function accountExists(PSID) {
        d("accountExists")
        !fileExists(userAccountsPath) && createUserAccountsFile()

        const result = readUserAccounts().hasOwnProperty(PSID)

        d("accountExists", `Account ${PSID} existence: ` + result)

        return result
    }

    function checkToken(token, type = "PSID") {
        d("checkToken")
        d("checkToken", `Token Value: ${token}, Type: ${type}`)
        if (type == "PSID") {
            if (!token) {

                d("checkToken", "Empty token. Token failed.")
                return {
                    "status": "fail",
                    "message": `${MESSAGES.emptyToken}${MESSAGES.findToken}And use it like Eg: GenerateTokens('MY __Secure-1PSID TOKEN HERE')`
                }
            }
            if (!token.endsWith(".")) {

                d("checkToken", "Invalid Token. Token failed.")
                return {
                    "status": "fail",
                    "message": `${MESSAGES.invalidToken}${MESSAGES.findToken}`
                }
            }
        }
        d("checkToken", "Token passed")
        return {
            "status": "pass"
        }
    }

    function gatherTokens(dataObj) {

        return new Promise(function (resolve) {
            d("gatherTokens")
            d("gatherTokens", "Recieved Object Parameter: " + dataObj)
            if (dataObj && !!dataObj.message) {
                DEBUG = dataObj.DEBUG
                if (checkToken(dataObj.PSID).status == "pass") {

                    const c_id = dataObj.c_id ? dataObj.c_id : (accountExists(dataObj.PSID) && readUserAccounts()[dataObj.PSID].c_id) ? readUserAccounts()[dataObj.PSID].c_id : ""

                    const r_id = dataObj.r_id ? dataObj.r_id : (accountExists(dataObj.PSID) && readUserAccounts()[dataObj.PSID].r_id) ? readUserAccounts()[dataObj.PSID].r_id : ""

                    const rc_id = dataObj.rc_id ? dataObj.rc_id : (accountExists(dataObj.PSID) && readUserAccounts()[dataObj.PSID].rc_id) ? readUserAccounts()[dataObj.PSID].rc_id : ""

                    const captcha = dataObj.captcha ? dataObj.captcha : (accountExists(dataObj.PSID) && readUserAccounts()[dataObj.PSID].captcha) ? readUserAccounts()[dataObj.PSID].captcha : ""


                    if (dataObj.SNLM0e) {
                        SNLM0e = dataObj.SNLM0e
                        addAccount({
                            "PSID": dataObj.PSID,
                            "SNLM0e": dataObj.SNLM0e,
                            "c_id": c_id,
                            "r_id": r_id,
                            "rc_id": rc_id,
                            "captcha": captcha
                        })
                        resolve({
                            "status": "pass",
                            "message": dataObj.message,
                            "PSID": dataObj.PSID,
                            "SNLM0e": dataObj.SNLM0e,
                            "c_id": c_id,
                            "r_id": r_id,
                            "rc_id": rc_id,
                            "captcha": captcha
                        })
                    } else if (accountExists(dataObj.PSID) && readUserAccounts()[dataObj.PSID].SNLM0e) {
                        resolve({
                            "status": "pass",
                            "message": dataObj.message,
                            "PSID": dataObj.PSID,
                            "SNLM0e": readUserAccounts()[dataObj.PSID].SNLM0e,
                            "c_id": c_id,
                            "r_id": r_id,
                            "rc_id": rc_id,
                            "captcha": captcha
                        })
                    } else {
                        resolve(fetch(URI.baseURI, {
                            "headers": {
                                "cookie": `__Secure-1PSID=${dataObj.PSID}; ` + (dataObj.CAPTCHA ? "GOOGLE_ABUSE_EXEMPTION=" + dataObj.CAPTCHA : "")
                            }
                        })
                            .then(data => data.text())
                            .then(data => {
                                if (data.includes(MESSAGES.googleCaptchaMessage)) {
                                    if (dataObj.CAPTCHA == "")
                                        return {
                                            "status": "fail",
                                            "message": `You are blocked by captcha.${MESSAGES.findCaptcha} Please see the documentation for this issue.`
                                        }
                                    return {
                                        "status": "fail",
                                        "message": `Your captcha token is outdated or invalid, regenerate a new one.${MESSAGES.findCaptcha}`
                                    }
                                }
                                return data.match(/"SNlM0e":"(.*?)"/);
                            })
                            .then(data => {
                                if (!data)
                                    return {
                                        "status": "fail",
                                        "message": `Looks like we can't find the SNLM0e token.${MESSAGES.findSnl}`
                                    }
                                addAccount({
                                    "PSID": dataObj.PSID,
                                    "SNLM0e": data[1],
                                    "c_id": c_id,
                                    "r_id": r_id,
                                    "rc_id": rc_id,
                                    "captcha": captcha
                                })
                                return {
                                    "status": "pass",
                                    "message": dataObj.message,
                                    "PSID": dataObj.PSID,
                                    "SNLM0e": data[1],
                                    "c_id": c_id,
                                    "r_id": r_id,
                                    "rc_id": rc_id,
                                    "captcha": captcha
                                }
                            }))
                    }

                }
                resolve(checkToken(dataObj.PSID))
            }
            resolve({
                "status": "fail",
                "message": "Empty message is not allowed"
            })
        })

    }

    function gatherResponse(dataObj) {
        return new Promise(function (resolve) {
            d("gatherResponse")
            d("gatherResponse", "Recieved Object Parameter: " + JSON.stringify(dataObj))
            let body = "f.req=" + encodeURIComponent(`[null, ${JSON.stringify(JSON.stringify([[dataObj.message], ["en"], [dataObj.c_id, dataObj.r_id, dataObj.rc_id]]))}]`) + "&at=" + encodeURIComponent(dataObj.SNLM0e)

            d("gatherResponse", "Body for fetch: " + body)

            fetch(URI.bardURI, {
                "headers": {
                    "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
                    "cookie": `__Secure-1PSID=${dataObj.PSID};`
                },
                "body": body,
                "method": "POST"
            })
                .then(data => data.text())
                .then(data => data.slice(data.indexOf('[["'), data.lastIndexOf('"]]') + 3))
                .then(data => {
                    d("gatherResponse", "Bard response: " + data)
                    try {
                        data = JSON.parse(JSON.parse(data)[0][2])
                        return data
                    } catch {
                        return {
                            "status": "fail",
                            "message": "Failed to parse response JSON from bard.google.com."
                        }
                    }
                })
                .then(data => {

                    data = {
                        "status": "pass",
                        "message": data[4][0][1][0],
                        "c_id": data[1][0],
                        "r_id": data[1][1],
                        "rc_id": data[4][0][0],
                        "questions": data[2] ? data[2].map((elem) => { if (elem) return elem[0] }) : [],
                        "images": data[4][0][4] ? data[4][0][4].map(elem => elem[1][3]) : [],
                        "image_source": data[4][0][4] ? data[4][0][4].map(elem => elem[1][0][0]) : [],
                        "message_source": data[4][0][2] != [] && data[4][0][2] != null && data[4][0][2][0] ? data[4][0][2][0].map(elem => elem[2][0]) : []
                    }
                    resolve(data);
                })
        })
    }

    async function prompt(dataObj) {
        const data = await gatherTokens(dataObj);
        if (data.status == "pass") {
            return gatherResponse(data)
                .then(dataObjs => {
                    addAccount({
                        "PSID": dataObj.PSID,
                        "SNLM0e": dataObj.SNLM0e,
                        "c_id": dataObjs.c_id,
                        "r_id": dataObjs.r_id,
                        "rc_id": dataObjs.rc_id
                    });
                    return dataObjs;
                });
        }
        return data;
    }

    function ask() {
        rl.question("\033[35mYou: \033[34m> \033[36m", (msg) => {
            if (msg == "c") {
                process.stdout.write('\033c');
                ask()
            } else if (msg.toLowerCase() == "b") {
                mainMenu()
            } else if (msg.toLowerCase() == "e") {
                process.exit(0);
            } else {
                prompt({
                    "PSID": SETTINGS.psid(),
                    "message": msg
                }).then(data => {
                    console.log("😊 : \033[34m" + data.message)
                    ask()
                })
            }
        })
    }

    ask()
}

function initHuggingface() {

    const token = SETTINGS.hftoken().replace(", ", ",").split(",")[0]
    const hfchat = SETTINGS.hftoken().replace(", ", ",").split(",")[1]

    const cookie = `token=${token}; hf-chat=${hfchat}`

    function hug(msg) {
        return new Promise(async (resolve) => {
            if (!token) resolve("Huggingface token not provided. Assign form the settings")
            if (!hfchat) resolve("hfchat not provided. Assign form the settings")

            let data = process.env.CONV ? { "conversationId": process.env.CONV } : await newConversationId().then(data => data)

            process.env.CONV = data.conversationId
            fetch(`https://huggingface.co/chat/conversation/${data.conversationId}/__data.json?x-sveltekit-invalidated=1_1`, {
                "headers": {
                    "cookie": cookie
                },
                "body": null,
                "method": "GET"
            })
                .then(() => {
                    fetch(`https://huggingface.co/chat/conversation/${data.conversationId}`, {
                        "headers": {
                            "content-type": "application/json",
                            "cookie": cookie
                        },
                        "body": JSON.stringify({
                            "inputs": msg,
                            "parameters": {
                                "temperature": 0.2,
                                "truncate": 1000,
                                "max_new_tokens": 1024,
                                "stop": [
                                    "</s>"
                                ],
                                "top_p": 0.95,
                                "repetition_penalty": 1.2,
                                "top_k": 50,
                                "return_full_text": false
                            },
                            "stream": true,
                            "options": {
                                "id": crypto.randomUUID(),
                                "response_id": crypto.randomUUID(),
                                "is_retry": false,
                                "use_cache": false,
                                "web_search_id": ""
                            }
                        }),
                        "method": "POST"
                    }).then(dataa => dataa.text())
                        .then(dataa => {
                            dataa = JSON.parse(dataa.slice(dataa.lastIndexOf('data:{"token":{') + 'data:'.length)).generated_text
                            resolve(dataa)
                        })
                })

        })
    }
    function newConversationId() {
        return new Promise((resolve) => {
            fetch("https://huggingface.co/chat/conversation", {
                "headers": {
                    "content-type": "application/json",
                    "cookie": cookie
                },
                "body": "{\"model\":\"OpenAssistant/oasst-sft-6-llama-30b-xor\"}",
                "method": "POST"
            }).then(data => data.json())
                .then(data => resolve(data))
        })
    }
    function ask() {
        rl.question("\033[35mYou: \033[34m> \033[36m", (msg) => {
            if (msg == "c") {
                process.stdout.write('\033c');
                ask()
            } else if (msg.toLowerCase() == "b") {
                mainMenu()
            } else if (msg.toLowerCase() == "e") {
                process.exit(0);
            } else {
                hug(msg).then(data => {
                    console.log("😊 : \033[34m" + data)
                    ask()
                })
            }
        })
    }

    intro()

    ask()
}

function initChatgptA1() {
    function decryptDES(cipherText, key, iv) {
        try {
            // Convert the key, ciphertext, and IV from Base64 to binary buffers
            const keyBuffer = Buffer.from(key, 'base64');
            const cipherTextBuffer = Buffer.from(cipherText, 'base64');
            const ivBuffer = Buffer.from(iv, 'base64');

            // Create a decipher object with 'des-cbc' algorithm
            const decipher = crypto.createDecipheriv('des-cbc', keyBuffer, ivBuffer);

            // Perform the decryption and get the plaintext (output as a Buffer)
            let decryptedBuffer = decipher.update(cipherTextBuffer);
            decryptedBuffer = Buffer.concat([decryptedBuffer, decipher.final()]);

            // Convert the decrypted Buffer to a string
            const decryptedText = decryptedBuffer.toString('utf-8');

            return decryptedText;
        } catch (error) {
            console.error('Decryption error:', error);
            return null;
        }
    }

    const url = 'https://chatai.wecall.info/chat_new';
    //20190826,00514321,des,cbc,pkcs5padding
    const headers = {
        'Host': 'chatai.wecall.info',
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': '168',
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': 'okhttp/4.10.0',
    };

    let dataa = {
        conversation: [{
            answer: "hi",
            question: "Hi how can i help you?",
        }],
        query: '',
    };



    function ask() {
        rl.question("\033[35mYou: \033[34m> \033[36m", (msg) => {
            if (msg == "c") {
                process.stdout.write('\033c');
                ask()
            } else if (msg.toLowerCase() == "b") {
                mainMenu()
            } else if (msg.toLowerCase() == "e") {
                process.exit(0);
            } else {
                dataa.query = msg;

                const options = {
                    method: 'POST',
                    headers,
                    body: JSON.stringify(dataa),
                };
                fetch(url, options)
                    .then(response => {
                        return response.text();
                    })
                    .then(data => {
                        dataa.conversation.push({
                            answer: data,
                            question: msg
                        });
                        console.log("😊 : \033[34m" + data)
                        ask();
                    });
            }
        })
    }

    intro()

    ask()

}

function initChatgptA2() {
    const url = 'https://chatgpt.vulcanlabs.co/api/v3/chat';

    function base64UrlEncode(data) {
        const encoded = Buffer.from(JSON.stringify(data)).toString('base64');
        return encoded.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    }

    function createJwtToken(payload, secret) {
        const header = {
            alg: 'HS256',
            typ: 'JWT',
        };

        const base64UrlHeader = base64UrlEncode(header);
        const base64UrlPayload = base64UrlEncode(payload);

        const signature = crypto
            .createHmac('sha256', secret)
            .update(`${base64UrlHeader}.${base64UrlPayload}`)
            .digest('base64');

        const base64UrlSignature = signature.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

        return `${base64UrlHeader}.${base64UrlPayload}.${base64UrlSignature}`;
    }


    const payload = {
        'token': 'admin',
        'exp': (new Date()).getTime()
    };

    const secret = 'vulcan@v4-chatgpt';

    const jwtToken = createJwtToken(payload, secret);

    const headers = {
        'Host': 'chatgpt.vulcanlabs.co',
        'Authorization': 'Bearer ' + jwtToken,
        'Accept': 'application/json',
        'User-Agent': 'Chat GPT Android 2.9.0 312 Android SDK: 31 (12)',
        'Content-Type': 'application/json; charset=utf-8',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
    };

    let body = {
        model: 'gpt-3.5-turbo',
        user: 'F31670D2A2254746',
        messages: [],
        nsfw_check: true,
    };

    function ask() {
        rl.question("\033[35mYou: \033[34m> \033[36m", (msg) => {
            if (msg == "c") {
                process.stdout.write('\033c');
                ask()
            } else if (msg.toLowerCase() == "b") {
                mainMenu()
            } else if (msg.toLowerCase() == "e") {
                process.exit(0);
            } else {
                body.messages.push({
                    'role': 'user',
                    'content': msg
                })


                const requestOptions = {
                    method: 'POST',
                    headers: headers,
                    body: JSON.stringify(body),
                };

                fetch(url, requestOptions)
                    .then(response => response.json())
                    .then(data => {

                        body.messages.push(data.choices[0].Message)
                        console.log("😊 : \033[34m" + data.choices[0].Message.content)
                        ask()
                    })
                    .catch(error => {
                        console.error('Error:', error);
                    });
            }
        })
    }

    intro()

    ask()

}

function initImagegenA1() {

    async function makeMultipartRequest(prompt, msg) {
        const url = 'https://api-img-gen-wrapper.apero.vn/api/v2/image-ai';
        const token = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwbGF0Zm9ybSI6ImlvcyIsImlhdCI6MTUxNjIzOTAyMn0.x6IpwVBb5g1bNLEsFjfGoghj0RVIhIXp2EGJaShka3k'; // Replace with your actual Bearer token

        const formData = new FormData();
        formData.append('file', fs.createReadStream(msg), {
            filename: 'temp_file_.png',
            contentType: 'image/*',
        });

        formData.append('prompt', `
    ${prompt}, ((fantasy style)), masterpiece, 8K resolution, concept art, highly detailed, cinematic render, beautiful and aesthetic, best quality, elegant, (vivid colours),  romanticism,  imaginative, magical, mystical, enchanting, surreal, heroic, medieval, epic scenery, rich detail, heroic characters, imagination
  `);

        const headers = {
            Authorization: `Bearer ${token}`,
            Device: 'android',
            'App-Name': 'Artimind',
            Accept: 'application/json',
        };

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers,
                body: formData,
            });

            if (!response.ok) {
                throw new Error('Request failed');
            }

            const imageArrayBuffer = await response.arrayBuffer(); // Get the image data as an ArrayBuffer
            fs.writeFileSync('output_image.png', Buffer.from(imageArrayBuffer)); // Save the image to a file

            console.log(`   ${CONSTANTS.INFO} Image saved in `, path.join(__dirname, "output_image.png"));

            console.log(`   ${CONSTANTS.INFO} Redirecting to plugin's home...`)
            setTimeout(availableMethods["4"].init, 5000);
        } catch (error) {
            console.error('Error:', error.message);
        }
    }

    function ask() {
        rl.question(`   ${CONSTANTS.ASK} Image File Path: `, (msg) => {
            if (msg == "c") {
                process.stdout.write('\033c');
                ask()
            } else if (msg.toLowerCase() == "b") {
                mainMenu()
            } else if (msg.toLowerCase() == "e") {
                process.exit(0);
            } else {
                try {
                    fs.accessSync(msg, fs.constants.F_OK, () => { })
                    rl.question(`   ${CONSTANTS.ASK} Your Prompt: `, (prompt) => {
                        if (!prompt && !msg) {
                            //ask()
                        } else {
                            makeMultipartRequest(prompt, msg)
                        }
                    })
                } catch {
                    console.log(`   ${CONSTANTS.ERROR} ${msg} doesn't exist.`);
                    ask()
                }

            }
        })
    }

    intro()

    ask()

}

function intro() {
    process.stdout.write('\033c');
    console.log(`\n   ${CONSTANTS.STAR} AI ToolKit`);
    console.log(`   ${CONSTANTS.INFO}${COLORS.BMAGENTA} v 1.0.0.1 ${COLORS.END}  ${CONSTANTS.RATE}${COLORS.RWHITE} erucix ${COLORS.END}  ${COLORS.BBLUE} S ${COLORS.END}${COLORS.RWHITE} Settings ${COLORS.END}    ${COLORS.BBLUE} B ${COLORS.END}${COLORS.RWHITE} Back ${COLORS.END}   ${COLORS.BBLUE} E ${COLORS.END}${COLORS.RWHITE} Exit ${COLORS.END}\n`);
}

function settings() {
    intro()

    let menuString = ``;

    let totalElements = (Object.keys(availableMethods).length / 2).toFixed()

    for (let index = 0; index <= totalElements; index++) {
        menuString += `   ${COLORS.YELLOW}${index + 1}${COLORS.END} ${availableMethods[index].sname}`
        if (availableMethods.hasOwnProperty(index + 4)) {
            menuString += `    ${COLORS.YELLOW}${Number(index) + 5}${COLORS.END} ${availableMethods[index + 4].sname}`
        }
        menuString += `\n`
    }

    console.log(menuString)

    rl.question(`\n   ${COLORS.BPINK} > ${COLORS.END} `, (msg) => {
        if (availableMethods.hasOwnProperty(Number(msg) - 1)) {
            availableMethods[Number(msg) - 1].sinit()
        } else if (msg.toLowerCase() == "e") {
            process.exit(0)
        } else if (msg.toLowerCase() == "b") {
            mainMenu()
        } else {
            console.log(`\n   ${CONSTANTS.ERROR} Invalid option selected.`);
            setTimeout(settings, 2000);
        }

    })
}

function mainMenu() {
    intro();
    let menuString = ``;

    let totalElements = (Object.keys(availableMethods).length / 2).toFixed()

    for (let index = 0; index <= totalElements; index++) {
        menuString += `   ${COLORS.YELLOW}${index + 1}${COLORS.END} ${availableMethods[index].name}`
        if (availableMethods.hasOwnProperty(index + 4)) {
            menuString += `    ${COLORS.YELLOW}${Number(index + 1) + 4}${COLORS.END} ${availableMethods[index + 4].name}`
        }
        menuString += `\n`
    }

    console.log(menuString);

    rl.question(`\n   ${COLORS.BPINK} > ${COLORS.END} `, (msg) => {

        if (availableMethods.hasOwnProperty(Number(msg) - 1)) {
            process.stdout.write('\033c');
            availableMethods[Number(msg) - 1].init()
        } else if (msg.toLowerCase() == "s") {
            settings();
        } else if (msg.toLowerCase() == "e") {
            process.exit(0);
        } else if (msg.toLowerCase() == "b") {
            process.exit(0);
        } else {
            console.log(`\n   ${CONSTANTS.ERROR} Invalid option selected.`);
            setTimeout(mainMenu, 2000);
        }
    });
}

const availableMethods = {
    "0": {
        "name": "Google Bard",
        "init": function () {
            initBard()
        },
        "sname": "Edit Bard Token       ",
        "sinit": function () {
            intro();

            console.log(`   ${CONSTANTS.AINFO} Current PSID: ${SETTINGS.psid()}`);

            rl.question(`\n   ${CONSTANTS.ASK} Your __Secure-1PSID: `, (msg) => {
                if (msg.toLowerCase() == "b") {

                    settings();

                } else if (msg.toLowerCase() == "e") {

                    process.exit(0);

                } else {
                    fs.writeFile(path.join(CONSTANTS.DIR, 'psid.txt'), msg, () => {
                        console.log(`   ${CONSTANTS.AINFO} Saved. Redirecting to settings...`)

                        setTimeout(settings, 2000)
                    });
                }
            })
        }
    },
    "1": {
        "name": "HuggingFace",
        "init": function () {
            initHuggingface()
        },
        "sname": "Add HuggingFace Tokens",
        "sinit": function () {
            intro();

            console.log(`   ${CONSTANTS.AINFO} Current Credidentials: ${SETTINGS.hftoken()}`);

            rl.question(`\n   ${CONSTANTS.ASK} Your token and hf-chat value seperated by comma(,): `, (msg) => {
                if (msg.toLowerCase() == "b") {

                    settings()

                } else if (msg.toLowerCase() == "e") {

                    process.exit(0);

                } else {
                    fs.writeFile(path.join(CONSTANTS.DIR, 'hftoken.txt'), msg, () => {
                        console.log(`   ${CONSTANTS.AINFO} Saved. Redirecting to settings...`)

                        setTimeout(settings, 2000)
                    });
                }
            })
        }
    },
    "2": {
        "name": "ChatGPT A1 ",
        "init": function () {
            initChatgptA1()
        },
        "sname": "No setting for this plugin",
        "sinit": function () {
            settings()
        }
    },
    "3": {
        "name": "ChatGPT A2",
        "init": function () {
            initChatgptA2()
        },
        "sname": "No setting for this plugin",
        "sinit": function () {
            settings()
        }
    },
    "4": {
        "name": "ImageGen A1",
        "init": function () {
            initImagegenA1()
        },
        "sname": "No setting for this plugin",
        "sinit": function () {
            settings()
        }
    }
}

fs.mkdir(CONSTANTS.DIR, () => { });

mainMenu();