const crypto = require("crypto");
const  {Buffer} = require("node:buffer");
const { buffer } = require("node:stream/consumers");

function sign(payload,SecretKey){
        const header ={
                alg:"HS256",                                            //creating header
                typ : "JWT"
        }
        const now =Math.floor(Date.now()/1000)                         // to get unix timestamp

        payload.iat=now;
        payload.exp=now + 15*60;                                         
        
        
        //converting object json to string

        const JSON_header =JSON.stringify(header);
        const JSON_payload=JSON.stringify(payload);


        //encoding string

        const encoded_header = Buffer
                        .from(JSON_header)
                        .toString("base64url");


        const encoded_payload =Buffer
                        .from(JSON_payload)
                        .toString("base64url")


        //making signature input so that we can make actual signature using HS256

        const signatureInput = encoded_header + "." + encoded_payload
        

        const signature =crypto 
                        .createHmac("sha256",SecretKey)                  //starting calculation
                        .update(signatureInput)                          //giving data for calculation
                        .digest("base64url");                           // final result
 


        // this is final jwt
        const token =encoded_header + "." + encoded_payload + "." + signature


        //DECODING

        // const dhead=Buffer                                                  //buffer is a built in fxn used for decoding
        //         .from(encoded_header,"base64url")
        //         .toString("utf8");                                          //base64url converts encoded header in bytes and we can 
        // const dobj =JSON.parse(dhead)                                        // convert those bytes to readable text usinf utf8
        // console.log("decoded header".dobj)


        // const dpayload=Buffer
        //         .from(encoded_payload,"base64url")
        //         .toString("utf8");
        // const dobjpay =JSON.parse(dpayload)
           
        // console.log("Decoded payload",dobjpay)


        return  token                                                                    //returning the final JWT
                
}

function verify(token,secretKey){

        const part=token.split(".");                                 //splitting JWT into 3 parts           H. P. S
        const orignalSign=part[2];
        const signatureInput=part[0]+"."+part[1];
        if (part.length !== 3){
                return false
        }


        //checking whether the signature is correct or not


        const expectedSign=crypto
                        .createHmac("sha256",secretKey)
                        .update(signatureInput)
                        .digest("base64url");

        
        //verifying the signature

        if (expectedSign!==orignalSign){
                return false                               //if signature is false return false
        }                                                  //otherwise continue and check expiration 
        

        //checking whether token is still valid or not using exp

        const encodedPayload =part[1];                
        const decodedPayload = Buffer                                                //getting exp and iat from payload
                        .from(encodedPayload,"base64url")
                        .toString("utf8");

        const objPayload=JSON.parse(decodedPayload);

        const exp =objPayload.exp;
        const iat = objPayload.iat


        const now = Math.floor(Date.now()/1000);
        if (exp ===undefined || now>=exp ){                   //checking jwt exp
                return false
        }
        return true;
}

module.exports = { sign, verify };             // allowing another file to use sign and verify