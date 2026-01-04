import mojoauthSdk from "mojoauth-sdk";
import dotenv from "dotenv";

dotenv.config();

const config = {
    apiKey: process.env.MOJOAUTH_API_KEY
};

const ma = mojoauthSdk(config);

export default ma;
