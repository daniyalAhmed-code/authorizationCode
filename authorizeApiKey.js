const AWS = require('aws-sdk');
// const AuthPolicy = require('aws-auth-policy');
const AuthPolicy = require('./auth-policy');
const log4js = require('log4js');
const logger = log4js.getLogger();
logger.level = process.env.LOG_LEVEL;
const dynamodb = new AWS.DynamoDB.DocumentClient();
const cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider();
const apiGatewayClient = new AWS.APIGateway();



// This method is used to create deny all policy
const deny = (awsAccountId, apiOptions) => {
    logger.info('Inside deny', awsAccountId, apiOptions);
    let policy = new AuthPolicy('', awsAccountId, apiOptions);
    policy.denyAllMethods();
    let iamPolicy = policy.build();
    return iamPolicy;
};

const getGroupPermissions = async (policy, payload,group, pathParameters) =>
{
    let user_groups = group.Groups;

    let tableName = "";
    // GET the cuid from payload
    // if cuid == 'admin' tableName = `${process.env.STAGE}-admin-role-membership`
    tableName = `${process.env.STAGE}-customer-role-membership`;
    console.log('tableName--', tableName);
    // Replace all cuid from user groups
    let user_groups_customer = [];
    for (let ug of user_groups) {
        user_groups_customer.push(ug.GroupName.replace(`${payload.cuid}-`, ''));
    }
    user_groups = user_groups_customer;
    // Get All Basepath Mappings 
     let basePathMappings = await getBasePathMappings(`${process.env.API_BASE_PATH_DOMAIN}`);
      console.log('basePathMappings---', basePathMappings);
    // Get all APIs a user can execute
    let apisResponse = await dynamodb.scan({ TableName: tableName }).promise();
    console.log('apisResponse---', apisResponse);
    // console.log('user_groups---', user_groups);
    // Get list of all
    for (let ar of apisResponse.Items) {
        // if (user_groups.includes(ar.role)) {
            
            for (let record of ar.apis) {
                const api_id = basePathMappings.find(element => element.basePath == record.api.split('/')[1]);
                var api_resource_path = record.api.split('/').slice(2).join('/');
                if (api_resource_path == ""){
                    api_resource_path = "/";
                }
                else{
                    api_resource_path = await getStrippedResource(api_resource_path, pathParameters);
                }
                // console.log('api_id---', api_id.restApiId);
                // console.log('api_resource_path---', api_resource_path);
                policy.allowMethodWithApi(AuthPolicy.HttpVerb[record.method], api_resource_path, api_id.restApiId);
            }
        //}
    }
    return policy;
};

const getBasePathMappings = async (domainName) => {
    var mappings = [];
    var params = {
      domainName: domainName /* required */
    };
    let apisResponse = await apiGatewayClient.getBasePathMappings(params).promise();
    // console.log('apisResponse---', apisResponse);
    // Get list of all
    for (let ar of apisResponse.items) {
        mappings.push(ar);
    }
    return mappings;
};

const hasEntityPermission = async (permittedOrganisations, requestEuid) =>
{
    let hasPermission = false;
    try {
        if (requestEuid == undefined)
        {
            hasPermission = false;
        }
        else if (requestEuid == `${process.env.EUID_TOKEN}`)
        {
            hasPermission = true;
        }
        else
        {
            // let permittedOrganisations = await getOrganisationList(cuid, euid);
            // console.log(`requestEuid`, requestEuid);
            // console.log(`permittedOrganisations`, permittedOrganisations);
            
            // let tableName = `entity-${cuid}`;
            // let response = await dynamodb.scan(
            //                     { 
            //                         TableName: tableName,
            //                         FilterExpression: "#entityId = :givenEntityId",
            //                         ExpressionAttributeNames: {
            //                             "#entityId": "euid",
            //                         },
            //                         ExpressionAttributeValues: {
            //                             ":givenEntityId": euid,
            //                         }
            //                     }).promise();
            // if (response.Count > 0)
            //     hasPermission = true;
            if (permittedOrganisations.includes(requestEuid)){
                hasPermission = true;
            }
        }
    }
    catch (ex) {
        console.log(ex);
    }
    return hasPermission;
};

const getStrippedResource = (resource, pathParameters) => {
    if (resource != "/") {
        Object.entries(pathParameters).forEach(entry => {
          let key = entry[0];
          let value = entry[1];
          resource = resource.replace('{' + key + '}', value);
        });
        resource = resource.replace(/{[a-zA-Z0-9\-_]+}/g, '*');
    }
    return resource.trim();
};


// This function is used to process the request
const processAuthRequest = async(payload,groups,awsAccountId, apiOptions, requestEuid, pathParameters) => {
    //cuid payload.cuid
    //euid payload.euid
    //sub payload.sub

    let permittedOrganisations = [];
    let CID = "";
    try{
        permittedOrganisations= await getOrganisationList(payload.cuid, (payload.euid));
        console.log(`permittedOrganisations`, permittedOrganisations);
    }
    catch (ex) {
        console.log(ex);
    }
    
    try{
        CID = await getCID(payload.cuid);
        console.log(`CID`, CID);
    }
    catch (ex) {
        console.log(ex);
    }
    
    
    if (!payload) {
        return deny(awsAccountId, apiOptions);
    }
    else {
        //Valid token. Generate the API Gateway policy for the user
        //Always generate the policy on value of 'sub' claim and not for
        // 'username' because username is reassignable
        //sub is UUID for a user which is never reassigned to another user.
        const pId = payload.sub;
        let policy = new AuthPolicy(pId, awsAccountId, apiOptions);

        // Check the Cognito group entry for permissions.
        // precedence

        if (groups && payload.euid) {
            policy = await getGroupPermissions(policy, payload,groups, pathParameters);
            if (!(await hasEntityPermission(permittedOrganisations, requestEuid)))
            {
                logger.info('denied due to entity permissions');
                return deny(awsAccountId, apiOptions);
            }
        }
        else {
            return deny(awsAccountId, apiOptions);
        }

        // Get all the config
        let context = {};

        let iamPolicy = policy.build();

        let pool = payload.cuid
        try {

            context.pool = pool;
            context.user = JSON.stringify(payload);
            context.permittedOrganisations = JSON.stringify(permittedOrganisations);
            context.user_euid = payload.euid;
            context.cid = CID
        }
        catch (e) {
            logger.error(e);
        }

        iamPolicy.context = context;
        console.log(policy);
        console.timeEnd(`AUTHORIZER`);
        return iamPolicy;
    }
};

exports.handler = async(event, context, callback) => {
    console.time(`AUTHORIZER`);
    console.log('Inside event', event);
    const tmp = event.methodArn.split(':');
    const awsAccountId = tmp[4];
    const apiOptions = {
        region: tmp[3]
    };
    try {
        payload = {}
        const token = event.headers.Authorization;
        const requestEuid = "aws";
        let cuid = token.split("|")
        cuid = cuid[1]
        let tableName = `${process.env.STAGE}-customer-api-keys-${cuid}`;
        let params = {
            TableName : tableName,
            FilterExpression: "#apiKey = :apiKey",
            ExpressionAttributeNames: {
                "#apiKey": "key_secret"
            },
            ExpressionAttributeValues: {
                 ":apiKey": token
            }
        };    
        let valRes = await dynamodb.scan(params).promise();
        valRes = valRes['Items'][0];
        let resourceAttr = await getResources(cuid);
        let poolid = resourceAttr.Item.attributes.poolid
        if((poolid != "")&&(!valRes.is_deleted)&&(!valRes.is_expired))
        {   
            let params = {
            Username: cuid, /* required */
            UserPoolId: poolid
         };
            let response = await cognitoidentityserviceprovider.adminGetUser(params).promise();
            let groups = await cognitoidentityserviceprovider.adminListGroupsForUser(params).promise();
            
            for( let items of response.UserAttributes){ 
                 if(items.Name == 'custom:euid')
                 {
                     payload["euid"] = items.Value
                 }
                 else if(items.Name == 'custom:cuid')
                 {
                     payload["cuid"] = items.Value
                 }
                 else if(items.Name == 'sub')
                 {
                     payload["sub"] = items.Value
                 }
             }
            return await processAuthRequest(payload,groups, awsAccountId, apiOptions, requestEuid, event.pathParameters);
        }
        else
        {
            return deny(awsAccountId, apiOptions);
        }
    
    }
    catch (err) {
        console.log(err);
        logger.error(err);
    }
    console.timeEnd(`AUTHORIZER`);
    return deny(awsAccountId, apiOptions);
}


const getResources = async (cuid) => {
    let valRes = ""
    let name = `${cuid}-userpool`;
    let params = {
        TableName: `${process.env.STAGE}-customer-resources`,
        Key: {
            "name": name
        }
    };
    valRes = await dynamodb.get(params).promise();

    if (valRes && 'Item' in valRes && valRes.Item && 'name' in valRes.Item && valRes.Item.name) {
        return valRes;
    }
    else {
        return valRes;
    }
}


const getOrganisationList = async (cuid, euid) => {
    let tableName = `entity-${cuid}`;
    let organisationsList = [euid];
    let sub_organisations = [];
    let params = {
        TableName : tableName,
        ProjectionExpression:"euid",
        FilterExpression: "#parent = :euidValue",
        ExpressionAttributeNames: {
            "#parent": "parent"
        },
        ExpressionAttributeValues: {
             ":euidValue": euid
        }
    };    
    
    var isDataPending = true;
    while (isDataPending){
        let valRes = await dynamodb.scan(params).promise();
        if (valRes && valRes.Count != 0) {
            valRes.Items.forEach(function(item) {
                sub_organisations.push(item.euid);
            });
        }
        if (typeof valRes.LastEvaluatedKey != "undefined") {
            params.ExclusiveStartKey = valRes.LastEvaluatedKey;
        }
        else{
            isDataPending = false;
        }

    }
    for(let org in sub_organisations){
        var child_organisations = await getOrganisationList(cuid, sub_organisations[org]);
        organisationsList =  organisationsList.concat(child_organisations);
    }
    
    return organisationsList;
};

const getCID = async (cuid) => {
    let CID = "";
    let tableName = `${process.env.STAGE}-customerid`;
    let params = {
        TableName : tableName,
        ProjectionExpression:"cid",
        FilterExpression: "#cuid = :cuid",
        ExpressionAttributeNames: {
            "#cuid": "cuid"
        },
        ExpressionAttributeValues: {
             ":cuid": cuid
        }
    };    
    
    let valRes = await dynamodb.scan(params).promise();
    if (valRes && valRes.Count > 0) {
        if (valRes.Items[0].cid) {
            CID = valRes.Items[0].cid
        }
    }
    
    return CID;
};

