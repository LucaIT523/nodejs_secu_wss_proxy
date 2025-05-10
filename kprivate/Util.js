const crypto = require('crypto');

function generateSecurePassword() {
    const uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ';  
    const lowercase = 'abcdefghijkmnopqrstuvwxyz'; 
    const numbers = '23456789';                     
    const symbols = '!()[]{}';
    
    const requiredChars = [
        uppercase[crypto.randomInt(uppercase.length)],
        lowercase[crypto.randomInt(lowercase.length)],
        numbers[crypto.randomInt(numbers.length)],
        symbols[crypto.randomInt(symbols.length)]
    ];
    
    const allValidChars = uppercase + lowercase + numbers + symbols;
    const remainingChars = Array.from({length: 8}, () => 
        allValidChars[crypto.randomInt(allValidChars.length)]
    );
    
    return [...requiredChars, ...remainingChars]
        .sort(() => crypto.randomInt(3) - 1)  
        .join('');
}

function safeZeroPad(input, length) {
    if (typeof input !== 'number' && isNaN(Number(input))) {
      return "";
    }
    return String(input).padStart(length, '0');
}

function generateUserName(listen_port, company_id, user_id) {

    let w_slisten_port = safeZeroPad(listen_port , 5);
    let w_scompany_id = safeZeroPad(company_id , 4);

    let w_sUserName = "kenan";
    
    if(w_slisten_port == "" || w_scompany_id == ""){
        return "";
    }

    return w_sUserName + w_slisten_port + w_scompany_id + String(user_id);

}

function parseUserName(username) {
    if (typeof username !== 'string' || username.length < 14) {
        return { status: 0, error: 'Invalid username format' };
    }

    const pattern = /^kenan(?<port>\d{5})(?<company>\d{4})(?<userid>.+)$/;
    const match = username.match(pattern);

    if (!match) {
        return { status: 0, error: 'Username pattern mismatch' };
    }

    try {
        return {
            status: 1,
            listen_port: parseInt(match.groups.port, 10),
            company_id: parseInt(match.groups.company, 10),
            user_id: match.groups.userid 
        };
    } catch (e) {
        return { status: 0, error: 'Number conversion failed'};
    }
}


module.exports = {
    generateSecurePassword,
    parseUserName,
    generateUserName,
};