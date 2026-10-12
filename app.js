
const myJWT = require("./my_jwt");

const payload = {
    userId: 101,
    role: "admin"
};

const secretKey = "my-secret-key";

const token = myJWT.sign(payload, secretKey);

console.log("Generated token:");
console.log(token);

const result = myJWT.verify(token, secretKey);

console.log("Verification result:", result);