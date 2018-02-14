/**
 * RelayUser
 * @module      :: Model
 */

var async = require('async');
var _ = require('lodash');
var NodeRSA = require('node-rsa');
var child_process = require('child_process');

module.exports = {
    
    tableName: 'relay_user',
    
    autoCreatedAt: false,
    autoUpdatedAt: false,
    autoPK: false,
    migrate: 'safe',
    
    attributes: {
        id: {
            type: 'integer',
            size: 11,
            primaryKey: true,
            autoIncrement: true
        },
        
        // Foreign key to HRIS
        ren_id: {
            type: 'integer',
            size: 11,
            unique: true,
        },
        
        rsa_public_key: {
            type: 'mediumtext'
        },
        
        rsa_private_key: {
            type: 'mediumtext'
        },
        
        //// Instance model methods
        
        toJSON: function() {
            // This model's data is not intended to be sent to the client.
            // But if for some reason that is done, the private key must
            // remain secret.
            var obj;
            if (this.toObject) {
                obj = this.toObject();
            } else {
                obj = _.clone(this);
            }
            delete obj.rsa_private_key;
            return obj;
        }
    },
    
    ////
    //// Life cycle callbacks
    ////
    
    
    
    ////
    //// Model class methods
    ////
    
    /**
     * Generate relay account & encryption keys for the given user.
     *
     * This is a slow process.
     * If an entry for the user already exists, it will be replaced.
     * 
     * @param {integer} renID
     * @return {Promise}
     */
    initializeUser: function(renID) {
        return new Promise((resolve, reject) => {
            if (!renID || renID <= 0) {
                reject(new Error('Invalid renID'));
                return;
            }
            
            var privateKey, publicKey;
            
            async.series([
            
                (next) => {
                    // Generate private key
                    child_process.exec('openssl genrsa 2048', (err, stdout) => {
                        if (err) next(err);
                        else {
                            privateKey = stdout;
                            next();
                        }
                    });
                },
                
                (next) => {
                    // Generate public key
                    var proc = child_process.exec('openssl rsa -outform PEM -pubout', (err, stdout) => {
                        if (err) next(err);
                        else {
                            publicKey = stdout;
                            next();
                        }
                    });
                    proc.stdin.write(privateKey);
                    proc.stdin.end();
                },
                
                (next) => {
                    // Save to database
                    RelayUser.query(`
                        
                        REPLACE INTO relay_user
                        SET
                            ren_id = ?,
                            rsa_private_key = ?,
                            rsa_public_key = ?
                        
                    `, [renID, privateKey, publicKey], (err) => {
                        if (err) next(err);
                        else next();
                    });
                },
                
            ], (err) => {
                if (err) reject(err);
                else resolve();
            });
            
            /*
            setImmediate(() => {
                var rsa = new NodeRSA({ b: 2048 });
                var privateKey = rsa.exportKey('private');
                var publicKey = rsa.exportKey('public');
                
                RelayUser.query(`
                    
                    REPLACE INTO relay_user
                    SET
                        ren_id = ?,
                        rsa_private_key = ?,
                        rsa_public_key = ?
                    
                `, [renID, privateKey, publicKey], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
            */
            
        });
    },
    
    
    /**
     * Create relay accounts for current workers in HRIS who don't have
     * accounts yet.
     * 
     * @return {Promise}
     */
    initializeFromHRIS: function() {
        return new Promise((resolve, reject) => {
            var hrisRen = [];
            var relayUsers = [];
            
            async.series([
                (next) => {
                    // Find active workers
                    LHRISWorker.query(`
                        
                        SELECT
                            w.ren_id
                        FROM
                            hris_worker w
                            JOIN hris_ren_data r
                                ON w.ren_id = r.ren_id
                        WHERE
                            r.statustype_id IN (3, 4, 5)
                            AND (
                                w.worker_terminationdate = '1000-01-01'
                                OR w.worker_terminationdate > NOW()
                            )
                        
                    `, [], (err, list) => {
                        if (err) next(err);
                        else {
                            hrisRen = list.map(x => x.ren_id) || [];
                            next();
                        }
                    });
                },
                
                (next) => {
                    // Find existing relay users
                    RelayUser.query(`
                        
                        SELECT ren_id
                        FROM relay_user
                        
                    `, [], (err, list) => {
                        if (err) next(err);
                        else {
                            relayUsers = list.map(x => x.ren_id) || [];
                            next();
                        }
                    });
                },
                
                (next) => {
                    var diff = _.difference(hrisRen, relayUsers);
                    console.log('Initializing ' + diff.length + ' relay accounts...');
                    
                    // Initialize new users one at a time
                    async.eachSeries(diff, (renID, userDone) => {
                        this.initializeUser(renID)
                        .then(() => {
                            console.log('...initialized user ' + renID);
                            userDone();
                        })
                        .catch((err) => {
                            userDone(err);
                        });
                    }, (err) => {
                        console.log('...done');
                        if (err) next(err);
                        else next();
                    });
                    
                    /*
                    var tasks = [];
                    diff.forEach((renID) => {
                        tasks.push(this.initializeUser(renID));
                    });
                    
                    Promise.all(tasks)
                    .then(() => {
                        console.log('Done');
                        next();
                    })
                    .catch((err) => {
                        next(err);
                    });
                    */
                }
            
            ], (err) => {
                if (err) {
                    console.log('Error initializing relay users from HRIS', err);
                    reject(err);
                }
                else resolve();
            });
        });
    }

};
