var packageVersion = require('./../package.json').version;
console.log("packageVersion :: " + packageVersion);

var loopback = require('loopback');
var boot = require('loopback-boot');
var jsonParser = require('body-parser').json();

var app = module.exports = loopback();

var APP_REALM = "iotsecuritydemoRealm";

var vcap_application = process.env.VCAP_APPLICATION;
var vcap_services = process.env.VCAP_SERVICES;

console.log("VCAP_APPLICATION="+vcap_application);
console.log("VCAP_SERVICES="+vcap_services);

var DEFAULT_MAX_EVENTS_RETRIEVED = 50;

//------------ Prepare for encryption/ decryption -----------------

var crypto = require('crypto');
var algorithm = 'aes-256-ctr';
var cryptoKey = 'your-key';

function encrypt(text){
  var cipher = crypto.createCipher(algorithm, cryptoKey);
  var crypted = cipher.update(text,'utf8','hex');
  crypted += cipher.final('hex');
  return crypted;
}
 
function decrypt(text){
  var decipher = crypto.createDecipher(algorithm, cryptoKey);
  var dec = decipher.update(text,'hex','utf8');
  dec += decipher.final('utf8');
  return dec;
}
 
//------------ Prepare the Cloudant DB -----------------

var cloudant;
var db;

var dbCredentials = {
		dbName : 'iotsecuritydemo'
	};

function charArrayToString(a) {
	var s = '';
	var i = 0; 
	while(i < a.length)
		s += String.fromCharCode(a[i++]);
	return s;
}

function initDBConnection() {
	if(! process.env.VCAP_APPLICATION)
		console.warn('VCAP_APPLICATION environment variable not found, using defaults.');
	
	if(! process.env.VCAP_SERVICES) 
		console.warn('VCAP_SERVICES environment variable not found, using defaults.');
		
	var vcapServices = JSON.parse(vcap_services);
	
	// Pattern match to find the first instance of a Cloudant service in
	// VCAP_SERVICES. If you know your service key, you can access the
	// service credentials directly by using the vcapServices object.
	
	for(var vcapService in vcapServices){
		if(vcapService.match(/cloudant/i)){
			dbCredentials.host = vcapServices[vcapService][0].credentials.host;
			dbCredentials.port = vcapServices[vcapService][0].credentials.port;
			dbCredentials.user = vcapServices[vcapService][0].credentials.username;
			dbCredentials.password = vcapServices[vcapService][0].credentials.password;
			dbCredentials.url = vcapServices[vcapService][0].credentials.url;
			
			break;
		}
	}
	
	cloudant = require('cloudant')(dbCredentials.url);
	
	// check if DB exists if not create
	cloudant.db.create(dbCredentials.dbName, function (err, res) {
		if (err) { 
			if(err.statusCode == 412)
				console.log('Using existing db.');
			else
				console.log('Could not create db ', err); 
		}
		else
			console.log('Created db.');
	});
	
	db = cloudant.use(dbCredentials.dbName);
	
	if(db == null){
		console.warn('Could not connect to the db. Data will be unavailable to the UI.');
	}

	var recTsDeviceIndex = 
		{
		  "index": {
			"fields": [
			  "recordType",
			  "timestamp",
			  "deviceId"
		    ]
		  },
		  "type": "json"
		};
	
	db.index(recTsDeviceIndex, function(err, response) {
		if(err) 
			console.log("Error creating index: "+JSON.stringify(err, null, 4));
		if(response)
			console.log("Response creating index: "+JSON.stringify(response, null, 4));
	});


	var recTsIndex = 
		{
		  "index": {
			"fields": [
			  "recordType",
			  "timestamp"
		    ]
		  },
		  "type": "json"
		};

	db.index(recTsIndex, function(err, response) {
		if(err) 
			console.log("Error creating index: "+JSON.stringify(err, null, 4));
		if(response)
			console.log("Response creating index: "+JSON.stringify(response, null, 4));
	});

} // end initDBConnection()

function stringify(doc) {
	var payload = JSON.parse(
			(typeof doc.payload == 'string' ? 
					decrypt(doc.payload) : 
					charArrayToString(doc.payload.data)));
	
	var result = '{' +
		'"_id":"'+ doc._id + '"' +
		', "_rev":"'+ doc._rev + '"' +
		', "recordType":"'+ doc.recordType + '"' +
		', "deviceType":"'+ doc.deviceType + '"' +
		', "deviceId":"'+ doc.deviceId + '"' +
		', "eventType":"'+ doc.eventType + '"' +
		', "format":"'+ doc.format + '"' +
		', "timestamp":"'+ doc.timestamp + '"' +
		', "payload":'+ JSON.stringify(payload) +
	'}';

	return result;
}

function getDeviceList(user, userGroup, callback) {
	var query;
	
	if(userGroup.roleAdmin == 'true')
		query = { selector: { 'recordType': 'status' } };
	else
		query = { selector: { 'recordType': 'status', '_id': {'$in': userGroup.devices} } };
	
	db.find(query, callback);
}

function getDevice(device_id, callback) {
	var query = { 
			'selector': { 'recordType': 'status', 'deviceId': device_id }
		};

	db.find(query, callback);
}

function getDeviceEvents(device_id, nofRecords, callback) {
	var query = { 
					'selector': { 'recordType': 'event', 'deviceId': device_id }, 
					'sort': [{'recordType': 'desc'}, {'timestamp': 'desc'}],
					'limit': nofRecords 
				};
	
	db.find(query, function(error, record) {
		var result;
		
		if(! error) {
			result = '{"docs":['; 
			
			var index = 0;
			
			if(index < record.docs.length) {
				result += stringify(record.docs[index]);
				index++;
				
				while(index < record.docs.length) {
					result += ', ' + stringify(record.docs[index]);
					index++;
				}
			}
			
			result += ']}';

			//console.log("Device list: "+result);
		}
		callback(error, result);
	});
}

function insertEventToDB(deviceType, deviceId, eventType, format, payload) {
	var encryptedPayload = encrypt(payload);
	
	// --- Insert the event record
		
	db.insert({
			"recordType" : "event",
			"deviceType" : deviceType,
			"deviceId" : deviceId,
			"eventType" : eventType,
			"format" : format,
			"timestamp" : JSON.parse(payload).d.timestampMillis,
			"payload" : encryptedPayload
		}, 
		'', // Generate id
		function(err, doc) {
			if(err) {
				console.log("Error creating event record: "+err);
			}
			if(doc) {
				console.log("Inserted: " + JSON.stringify(doc, null, 4));
				
				db.get(doc.id, function(err, record) {
						if(record) {
							var decryptedPayload = decrypt(record.payload);
							console.log("Decrypted payload: "+decryptedPayload);
						}  
					});
			}
		}
	);	
}

function insertStatusToDB(deviceType, deviceId, payload, topic) {
	// --- Insert the status record
	
	db.update({
			"recordType" : "status",
			"deviceType" : deviceType,
			"deviceId" : deviceId,
			"topic" : topic,
			"timestamp" : Date.parse(payload.Time),
			"payload" : encrypt(payload)
		}, 
		deviceId, // Generate id
		function(err, doc) {
			if(err) {
				console.log("Error creating/updating status record: "+JSON.stringify(err, null, 4));
			}
		}
	);	
}

function executeIfAllowed(user, deviceId, access, callback) {
	var userJson = JSON.stringify(user, null, 4);
	console.log('Calling user is: '+userJson);
	
	if('{}' == userJson) {
		callback(new Error("No user information provided in request."), null);
	}
	else {
		if(! user.attributes) {
			callback(new Error("User information does not have attributes."), null);
		}
		else {
			var attributes = JSON.parse(user.attributes);
			
			if(! attributes.userGroup) {
				callback(new Error("User information attributes do not have user group."), null);
			}
			else {
				db.get(attributes.userGroup, function(error, userGroup) {
					if(error) {
						callback(error, null);
					}
					else {
						console.log('User group is: '+JSON.stringify(userGroup, null, 4));
						
						if(userGroup.roleAdmin == 'true')
								callback(null, userGroup);
						else {
							if((deviceId != '') && (userGroup.devices.indexOf(deviceId) < 0))
								callback(new Error("User not authorized for this device."), userGroup);
							if((access == 'reader') && (userGroup.roleReader != 'true'))
								callback(new Error("User not authorized to access data of any device."), userGroup);
							else if((access == 'writer') && (userGroup.roleWriter != 'true'))
								callback(new Error("User not authorized to send command to any device."), userGroup);
							else
								callback(null, userGroup);
						}
					}
				});
			}
		}
	}
}
//------------ Connect to the db ----------------

initDBConnection();

var MAX_UPDATE_RETRY = 3;

db._update = function(obj, key, retry, callback) {
	if(retry > MAX_UPDATE_RETRY) {
		callback(new Error("Max update retries exceeded."), null);
		return;
	}
	
	var db = this;
	db.get(key, function (error, existing) { 
		if(!error) obj._rev = existing._rev;
		db.insert(obj, key, function(error, result) {
			if(error) {
				if(error.statusCode == 409)
					db._update(obj, key, retry+1, callback);
				else
					callback(error, null);
			}
		});
	});
}

db.update = function(obj, key, callback) {
	db._update(obj, key, 1, callback);
}

//-------- Prepare to connect to Watson IoT Platform ---------

var IotfClient = require("ibmiotf").IotfApplication;

// TODO externalize the configuration details
var vcapServices = JSON.parse(vcap_services);

var org;
var auth_key;
var auth_token;

// Pattern match to find the first instance of a IoTF service in
// VCAP_SERVICES. If you know your service key, you can access the
// service credentials directly by using the vcapServices object.

for(var vcapService in vcapServices){
	if(vcapService.match(/iotf/i)){
		org = vcapServices[vcapService][0].credentials.org;
		auth_key = vcapServices[vcapService][0].credentials.apiKey;
		auth_token = vcapServices[vcapService][0].credentials.apiToken;
		
		break;
	}
}

var iotConfig = {
	    "org" : org,
	    "id" : "iotsecuritydemo",
	    "auth-key" : auth_key,
	    "auth-token" : auth_token
	};

var iotfClient = new IotfClient(iotConfig);

iotfClient.connect();

iotfClient.on("error", function (err) {
    console.log("IoTF client error: "+err);
});

iotfClient.on("connect", function () {
		// Subscribe to status from all devices
		iotfClient.subscribeToDeviceStatus();
		
		// Subscribe to all events from all devices
    	iotfClient.subscribeToDeviceEvents();
    });

iotfClient.on("deviceEvent", function (deviceType, deviceId, eventType, format, payload) {
	// Handle events from devices
    console.log("Device Event from :: "+deviceType+" : "+deviceId+" of event "+eventType+" with payload : "+payload);
    //console.log("Device Event from :: "+deviceType+" : "+deviceId+" of event "+eventType);
    
    insertEventToDB(deviceType, deviceId, eventType, format, payload);
});

iotfClient.on("deviceStatus", function (deviceType, deviceId, payload, topic) {
	// Handle status updates from devices
    console.log("Device status from :: "+deviceType+" : "+deviceId+" with payload : "+payload);
    
    insertStatusToDB(deviceType, deviceId, payload, topic);
});

function sendCommandToDevice(device_id, command, data) {
	if(iotfClient.isConnected)
		getDevice(device_id, function(error, deviceStatus) {
			if(error) 
				throw error;
			else
				iotfClient.publishDeviceCommand(deviceStatus.deviceType, device_id, command, "json", data);
		});
	else
		throw new Error("Not connected to IoT Foundation.");
}

// ------------ Protecting mobile backend with Mobile Client Access -----------------

// Load passport (http://passportjs.org)
var passportMCA = require('passport');

// Get the MCA passport strategy to use
var MCABackendStrategy = require('bms-mca-token-validation-strategy').MCABackendStrategy;

// Tell passport to use the MCA strategy
passportMCA.use(new MCABackendStrategy());

// Tell application to use passport
app.use(passportMCA.initialize());

passportMCA.serializeUser(function(user, done) { 
	done(null, user); 
}); 
passportMCA.deserializeUser(function(obj, done) { 
	done(null, obj); 
}); 

// Protect /protected endpoint which is used to test the Mobile Client Access service
app.get('/protected', passportMCA.authenticate('mca-backend-strategy', {session: true}), function(req, res){
    console.log("Security context:", req.securityContext);
	res.send("Hello, this is a protected resource of the mobile backend application!");
});

// ------------ Custom Authentication to use with Mobile Client Access -----------------
//------------ Custom Authentication uses custom user documents in Cloudant -----------------

function isValidTenant(tenantId) {
	var vcapServices = JSON.parse(vcap_services);
	
	var targetTenantId = '';
	
	for(var vcapService in vcapServices){
		if(vcapService.match(/AdvancedMobileAccess/i)){
			targetTenantId = vcapServices[vcapService][0].credentials.tenantId;
			break;
		}
	}

	return ((targetTenantId != '') && (targetTenantId == tenantId));
}

function isValidRealm(realmName) {
	return (realmName == APP_REALM);
}

app.post('/apps/:tenantId/:realmName/startAuthorization', jsonParser, function(req, res){
	var tenantId = req.params.tenantId;
	var realmName = req.params.realmName;
	var headers = req.body.headers;

	console.log("startAuthorization: "+tenantId+", "+realmName+", "+JSON.stringify(headers, null, 4));
    console.log("Security context:", req.securityContext);

	var response = { status: "failure" };

	var validTenant = isValidTenant(tenantId);
	var validRealm = isValidRealm(realmName);
	
	if(validTenant && validRealm) {
		response = {
				status: "challenge",
				challenge: { text: "Enter username and password" }
			};
		console.log("Responding with challenge.");
		res.status(200).json(response);
	}
	else {
		if(! validTenant) {
			response.challenge = { text: "Wrong tenant id." };
		}
		else if(! validRealm) {
			response.challenge = { text: "Wrong realm." };
		}

		console.log("Responding with failure:" + JSON.stringify(response, null, 4));
		res.status(400).json(response);
	}
});

app.post('/apps/:tenantId/:realmName/handleChallengeAnswer', jsonParser, function(req, res){
	var tenantId = req.params.tenantId;
	var realmName = req.params.realmName;
	var challengeAnswer = req.body.challengeAnswer;

	console.log("handleChallengeAnswer: "+tenantId+", "+realmName+", "+JSON.stringify(challengeAnswer, null, 4));
    console.log("Security context:", req.securityContext);

	var username = req.body.challengeAnswer["username"];
	var password = req.body.challengeAnswer["password"];

	var response = { status: "failure" };

	var validTenant = isValidTenant(tenantId);
	var validRealm = isValidRealm(realmName);
	
	if(validTenant && validRealm) {
		// Retrieve custom user document from Cloudant db
		db.get(username, function(error, userIdentity) {
			var response = { status: "failure" };
			
			if(! error) {
				console.log("Retrieved from db: "+JSON.stringify(userIdentity, null, 4));

				if(encrypt(password) == userIdentity.password) {
					response.status = "success";
					response.userIdentity = userIdentity;
				}
				else
					error = new Error("Username or password mismatch.");
			}

			response.failure = error;

			if(response.status == "success") {
				console.log("Responding with success.");
				res.status(200).json(response);
			}
			else {
				console.log("Responding with failure:" + JSON.stringify(response, null, 4));
				res.status(400).json(response);
			}
		});
	}
	else {
		if(! validTenant) {
			response.challenge = { text: "Wrong tenant id." };
		}
		else if(! validRealm) {
			response.challenge = { text: "Wrong realm." };
		}

		console.log("Responding with failure:" + JSON.stringify(response, null, 4));
		res.status(400).json(response);
	}
});


// ------------ The custom API routes -----------------

var iotRouteBase = '/iotf';

app.get(iotRouteBase + '/devices', 
		passportMCA.authenticate('mca-backend-strategy', {session: true}), 
		function(req, res) {
    		console.log(iotRouteBase+'/devices entered.');
    		console.log("Security context: ", req.securityContext);
    		
			// Check for the user group and filter out the devices that the user does not have access to
			executeIfAllowed(req.user, '', 'reader', function(error, userGroup) {
				if(error) {
					console.log('Error: '+JSON.stringify(error, null, 4));
					res.status(400).json(error);
				}
				else {
					getDeviceList(req.user, userGroup, function(error, result) {
						if(error) {
							console.log('Error: '+JSON.stringify(error, null, 4));
							res.status(400).json(error);
						}
						else {
							console.log('Returning device list: ', result);
							res.status(200).send(result);
						}
					});
				}
			});
		}
);

app.get(iotRouteBase + '/devices/:id', 
		passportMCA.authenticate('mca-backend-strategy', {session: true}), 
		function(req, res) {
			console.log(iotRouteBase+'/devices/id entered.');
    		console.log("Security context: ", req.securityContext);
    		
			// Check for the user authorization for the device and reject as necessary
			console.log('Calling user is: '+JSON.stringify(req.user, null, 4));

			// If neither 'cmd' nor 'count' is present in req parameters, then assume default count
			var count = DEFAULT_MAX_EVENTS_RETRIEVED;
			var command = '';
			var commandData = '';

			// Check if 'cmd' parameter is present in request to send command to IoT device
			if(req.query.cmd) {
				command = req.query.cmd;
				
				if(req.query.data)
					commandData = req.query.data;
				
				console.log(
						'Sending command to device with id: '+req.params.id+
						', command: '+command+', data: '+commandData);
		
				executeIfAllowed(req.user, req.params.id, 'writer', function(error, userGroup) {
					if(error) {
						console.log('Error: '+JSON.stringify(error, null, 4));
						res.status(400).json(error);
					}
					else {
						try {
							sendCommandToDevice(req.params.id, command, commandData);
							
							res.setHeader('Content-Type', 'application/json');
							res.status(200).send('{ "status": "Published command to device"}');
						}
						catch(err) {
							res.status(400).json(err);
						}
					}
				});
				
				return;
			}
			// Check if 'count' parameter is present in request to retrieve IoT device data
			else if(req.query.count) {
				count = parseInt(req.query.count, 10); 
				
				console.log('Querying device with id: '+req.params.id+', count: '+count);

				executeIfAllowed(req.user, req.params.id, 'reader', function(error, userGroup) { 
					if(error)
						res.status(400).json(error);
					else {
						getDeviceEvents(req.params.id, count, function(error, result) {
							if(error)
								res.status(400).json(error);
							else {
								console.log('Returning device data: '+result);
								res.setHeader('Content-Type', 'application/json');
								res.status(200).send(result);
							}
						});
					}
				}); 
			}
		}
);


app.start = function () {
	// start the web server
	return app.listen(function () {
		app.emit('started');
		var baseUrl = app.get('url').replace(/\/$/, '');
		console.log('Web server listening at: %s', baseUrl);
		//var componentExplorer = app.get('loopback-component-explorer');
		//if (componentExplorer) {
		//	console.log('Browse your REST API at %s%s', baseUrl, componentExplorer.mountPath);
		//}
	});
};

// Bootstrap the application, configure models, datasources and middleware.
// Sub-apps like REST API are mounted via boot scripts.
boot(app, __dirname, function (err) {
	if (err) throw err;
	if (require.main === module)
		app.start();
});

