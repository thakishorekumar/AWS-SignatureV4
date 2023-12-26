//AWS API Gateway Signed Requests
//Video Playlist https://www.youtube.com/playlist?list=PLG0hGAptBFmEPkDaSu7m9qRWOzR6KFPUV
//Video https://www.youtube.com/watch?v=Pbt7_JHTUJk&list=PLG0hGAptBFmEPkDaSu7m9qRWOzR6KFPUV&index=6

import { SHA256, HmacSHA256 } from 'crypto-js';
import { AuthorizationRequest } from "../models/authorization-request.model"; 
import { AuthorizationResponse } from "../models/authorization-response.model";

export const getAuthorization = (event: any) => {
    return new Promise((resolve, reject) => {
        resolve(getHeader(event));
    });
};

const getHeader = (authData: AuthorizationRequest) => {
    var access_key = 'test';
    var secret_key = 'test+test'; 
    var region = 'us-east-1';
    var service = 'execute-api';

    // get the various date formats needed to form our request 
    var amzDate = this.getAmzDate(new Date().toISOString()); 
    var authDate = amzDate.split("T")[0];

    // get the SHA256 hash value for our payload
    var hashedContent = SHA256(authData.Content).toString();

    // create our canonical request
    var canonicalReq = authData.Method + '\n' +
                        authData.CanonicalURI + '\n' +
                        authData.CanonicalQueryString + '\n' + 
                        'host:' + authData.Host + '\n' +
                        'x-amz-content-sha256:' + hashedContent + '\n' + 
                        'x-amz-date:' + amzDate + '\n' +
                        '\n' +
                        'host;x-amz-content-sha256;x-amz-date' + '\n' + 
                        hashedContent;

    // hash the canonical request
    var canonicalReqHash = SHA256(canonicalReq).toString();

    // form our String-to-Sign
    var stringToSign = 'AWS4-HMAC-SHA256\n' +
                        amzDate + '\n' +
                        authDate +'/' + region + '/'+ service + '/aws4_request\n' + 
                        canonicalReqHash;

    // get our Signing Key
    var signingKey = this.getSignatureKey(secret_key, authDate, region, service);

    // Sign our String-to-Sign with our Signing Key 
    var authKey = HmacSHA256(stringToSign, signingKey);

    // Form our authorization header
    var authString = 'AWS4-HMAC-SHA256' +
                        'Credential='+
                        access_key+'/'+
                        authDate+'/'+
                        region+'/'+
                        service+'/aws4_request,'+ 
                        'SignedHeaders=host;x-amz-content-sha256;x-amz-date,'+ 
                        'Signature='+authKey;

    // throw our headers together 
    return {
        Date: amzDate,
        Authorization: authString, 
        Content: hashedContent
    } as AuthorizationResponse;
}

// this function gets the Signature Key, see AWS documentation for more details, this was taken from the AWS samples site 
const getSignatureKey = (key: string, dateStamp: any, regionName: any, serviceName: any) => {
    var kDate = HmacSHA256(dateStamp, "AWS4" + key); 
    var kRegion = HmacSHA256(regionName, kDate);
    var kService = HmacSHA256(serviceName, kRegion);
    var kSigning = HmacSHA256("aws4_request", kService); 
    return kSigning;
}

// this function converts the generic JS 1S08601 date format to the specific, l format the AWS API wants 
const getAmzDate = (dateStr: string) => {
    var chars = [":","-"];
    for (var i=0;1<chars.length;i++) {
        while (dateStr.index0f(chars[i]) != —1) {
            dateStr = dateStr.replace(chars[i],"");
        }
    }
    dateStr = dateStr.split(".")[0] + "Z"; 
    return dateStr;
}