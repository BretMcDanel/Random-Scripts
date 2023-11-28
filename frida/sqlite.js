/** This https://Frida.re script will assist in reviewing SQL statements to a 
 * Sqlite3 database via the SQLite dll/so/dynlib.  This can help you look for 
 * questional statements that might be prone to injection.
 */

// Everything is in an anonymous function to avoid collisions with other scripts
(function () {
    const dbHandles = []; // Holds the DB handle and statement handle properties
    const hookAll = false; // Whether to hook all functions, useful for debugging

    class sqliteObject {
        handle;
        filename;
        statement = [];

        /**
         * Database constructor
         * @constructor
         * @param {string} handle - The handle for the database connection
         * @param {string} filename - The filename associated with this database.
         * @returns {object} dbObject.database - The database object just created
         */
        constructor(handle, filename) {
            this.handle = handle;
            this.filename = filename;
        }

        /**
         * Sets the database entry.
         * @param {string} handle - The handle for the database connection
         * @param {string} filename - The filename associated with this database.
         * @returns {object} dbObject.database - The database object just created
         */
        static set(handle, filename) {
            if (this.getDB(handle)) {
                console.log("[i] Database handle already exists.");
            } else {
                return this.databases[this.databases.push({
                    handle: handle,
                    filename: filename
                }) - 1];
            }
        }

        /**
         * Returns a database entry.
         * @param {string} handle - The handle for the database connection
         * @returns {object} dbObject.database - The database object that matches the handle
         */
        static find(dbArray, handle) {
            return dbArray[Object.keys(dbArray).find(key => dbArray[key].handle === handle)];
        }

        /**
         * Gets the index of the database handle.
         * @param {array} dbArray - The array that holds all of the database connections
         * @param {string} handle - The handle for the database connection
         * @returns {int} index - The database index that matches the handle
         */
        static getIndex(dbArray, handle) {
            return dbArray.findIndex(function (dbh) { return dbh.handle === handle });
        }

        /**
         * Returns a database entry.
         * @param {string} database - The handle for the database connection
         * @param {string} handle - The handle for the statement
         * @param {string} sql - The sql for this statement
         * @returns {object} dbObject.database.statement - The statement object just created
         */
        addStatement(handle, sql) {
            if (this.statement === undefined) {
                this.statement = [];
            }
            var stmtIndex = this.statement.findIndex(function (statement) { return statement.handle === handle });
            if (stmtIndex >= 0) {
                this.statement[stmtIndex] = {
                    handle: handle,
                    sql: sql
                }
                return this.statement[stmtIndex];
                //console.log("[!] Statement handle already exists.");
            } else {
                return this.statement[this.statement.push({
                    handle: handle,
                    sql: sql
                }) - 1];
            }
        }

        /**
         * Adds an argument count to a given statement.
         * @param {string} handle - The handle for the database connection
         * @param {int} count - the count to add
         * @returns {object} dbObject.database - The database object that matches the handle
         */
        addStatementArgCount(handle, count) {
            if (this.statement === undefined) {
                console.log("[!] No statements found.");
                return;
            }
            var stmtIdx = this.statement.findIndex(function (statement) { return statement.handle === handle });
            if (stmtIdx >= 0) {
                this.statement[stmtIdx].argCount = count;
                return this;
            } else {
                console.log("[!] Statement handle not found.");
            }
        }

        /**
         * Adds an argument to a given statement.
         * @param {string} handle - The handle for the database connection
         * @param {string} arg - The argument to add
         * @param {int} index - the index of the argument
         * @returns {object} dbObject.database.statement - The database object that matches the handle
         */
        addStatementArgument(handle, arg, index) {
            if (this.statement === undefined) {
                console.log("[!] No statements found.");
                return;
            }
            var stmtIdx = this.statement.findIndex(function (statement) { return statement.handle === handle });
            if (stmtIdx >= 0) {
                if (this.statement[stmtIdx].arguments == undefined) {
                    this.statement[stmtIdx].arguments = {};
                }
                this.statement[stmtIdx].arguments[index] = arg;

                return this;
            } else {
                console.log("[!] Statement handle not found.");
            }
        }

        /**
         * Gets the index of a given statement.
         * @param {string} handle - The handle for the database connection
         * @returns {int} index - The index for the statement
         */
        getStatementIndex(handle) {
            if (this.statement === undefined) {
                console.log("[!] No statements found.");
                return;
            }
            return this.statement.findIndex(function (statement) { return statement.handle === handle });
        }

        /**
         * Gets the arguments for a given statement
         * @param {int} index - the count to add
         * @returns {object} dbObject.database.statement - The statement object that matches the handle
         */
        getStatementArguments(index) {
            if (this.statement[index].arguments === undefined) {
                console.log("[!] No statements found.");
                return;
            }
            var ordered = Object.keys(this.statement[index].arguments).sort().reduce(
                (obj, key) => {
                    obj[key] = this.statement[index].arguments[key];
                    return obj;
                },
                {}
            );
            return ordered;
        }

        /**
         * Returns a database entry.
         * @param {string} handle - The handle for the database connection
         * @returns dbObject.database - The database object that matches the handle
         */
        static getDbByStatementHandle(dbArray, handle) {
            return dbArray.find(db => db.statement.some(stmt => stmt.handle === handle));
        }

        /**
         * Makes a printable representation of the properties in the object.
         * @returns {string} data - This object properties represented as JSON
         */
        static toString() {
            return JSON.stringify(this);
        }
    };


    Process.enumerateModules({
        onMatch: function (module) {
            if (module.name.startsWith("sqlite3.") || module.name.startsWith("e_sqlite.") || module.name == "libsqlite3.dylib") {
                console.log('[+] Module name: ' + module.name + " - " + "Base Address: " + module.base.toString());

                // This is used to get the SQL statements
                var func_sqlite3_sql = Module.findExportByName(module.name, 'sqlite3_sql');
                var func_sqlite3_expanded_sql = Module.findExportByName(module.name, 'sqlite3_expanded_sql');
                var sqlite3_sql = new NativeFunction(func_sqlite3_sql, 'char', ['pointer']);
                var sqlite3_expanded_sql = new NativeFunction(func_sqlite3_expanded_sql, 'char', ['pointer']);

                Module.enumerateExports(module.name, {
                    onMatch: function (e) {
                        var functionAddr = Module.findExportByName(null, e.name);
                        if (functionAddr != null) {
                            switch (e.name) {
                                case "sqlite3_open":
                                case "sqlite3_open16":
                                case "sqlite3_open_v2":
                                    console.log('[+] Hooking: ' + e.name + ' @ 0x' + functionAddr.toString(16));
                                    try {
                                        var filename;
                                        var dbHandle;
                                        Interceptor.attach(functionAddr, {
                                            onEnter: function (args) {
                                                filename = Memory.readUtf8String(args[0]);
                                                dbHandle = args[1];
                                            },
                                            onLeave: function (retvalue) {
                                                console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                console.log('\tFilename: "' + filename + '"');
                                                console.log('\tDB Handle: ' + dbHandle.readPointer().readPointer());
                                                dbHandles.push(new sqliteObject(dbHandle.readPointer().readPointer().toString(), filename));
                                            }
                                        });
                                    } catch (error) {
                                        console.error('\x1b[31m[!] Error: ' + error + '\x1b[0m]');
                                    }
                                    break;
                                case "sqlite3_close":
                                case "sqlite3_close_v2":
                                    console.log('[+] Hooking: ' + e.name + ' @ 0x' + functionAddr.toString(16));
                                    try {
                                        Interceptor.attach(functionAddr, {
                                            onEnter: function (args) {
                                                var dbhName = args[0].readPointer().toString();
                                                var dbh = sqliteObject.find(dbHandles, dbhName);
                                                if (dbh) {
                                                    console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                    console.log('\tDB Handle: ' + dbhName);
                                                    console.log('\tFilename: "' + dbh.filename + '"');
                                                    delete dbHandles[sqliteObject.getIndex(dbHandles, dbhName)];
                                                } else {
                                                    console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                    console.log('\tDB Handle: ' + dbhName);
                                                }
                                            },
                                            onLeave: function (retvalue) {
                                            }
                                        });
                                    } catch (error) {
                                        console.error('\x1b[31m[!] Error: ' + error + '\x1b[0m]');
                                    }
                                    break;
                                case "sqlite3_prepare":
                                case "sqlite3_prepare_v2":
                                    console.log('[+] Hooking: ' + e.name + ' @ 0x' + functionAddr.toString(16));
                                    try {
                                        var db;
                                        var stmt;
                                        var stmtHandle;
                                        Interceptor.attach(functionAddr, {
                                            onEnter: function (args) {
                                                db = args[0].readPointer().toString();
                                                stmt = Memory.readUtf8String(args[1]);
                                                stmtHandle = args[3];
                                            },
                                            onLeave: function (retvalue) {
                                                if (stmt != "BEGIN ") {
                                                    var dbh = sqliteObject.find(dbHandles, db);

                                                    dbh.addStatement(stmtHandle.readPointer().readPointer().toString(), stmt);
                                                    console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                    console.log('\tDB: "' + dbh.filename + '"');
                                                    console.log('\tSQL: "' + stmt + '"');
                                                }
                                            }
                                        });
                                    } catch (error) {
                                        console.error('\x1b[31m[!] Error: ' + error + '\x1b[0m]');
                                    }
                                    break;
                                case "sqlite3_prepare_v3":
                                    console.log('[+] Hooking: ' + e.name + ' @ 0x' + functionAddr.toString(16));
                                    try {
                                        var db;
                                        var stmt;
                                        var stmtHandle;
                                        Interceptor.attach(functionAddr, {
                                            onEnter: function (args) {
                                                db = args[0].readPointer().toString();
                                                stmt = Memory.readUtf8String(args[1]);
                                                stmtHandle = args[4];
                                            },
                                            onLeave: function (retvalue) {
                                                if (stmt != "BEGIN ") {
                                                    var dbh = sqliteObject.find(dbHandles, db);

                                                    dbh.addStatement(stmtHandle.readPointer().readPointer().toString(), stmt);
                                                    console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                    console.log('\tDB: "' + dbh.filename + '"');
                                                    console.log('\tSQL: "' + stmt + '"');
                                                }
                                            }
                                        });
                                    } catch (error) {
                                        console.error('\x1b[31m[!] Error: ' + error + '\x1b[0m]');
                                    }
                                    break;
                                case "sqlite3_prepare16":
                                case "sqlite3_prepare16_v2":
                                    console.log('[+] Hooking: ' + e.name + ' @ 0x' + functionAddr.toString(16));
                                    try {
                                        var db;
                                        var stmt;
                                        var stmtHandle;
                                        Interceptor.attach(functionAddr, {
                                            onEnter: function (args) {
                                                db = args[0].readPointer().toString();
                                                stmt = Memory.readUtf16String(args[1]);
                                                stmtHandle = args[3];
                                            },
                                            onLeave: function (retvalue) {
                                                if (stmt != "BEGIN ") {
                                                    var dbh = sqliteObject.find(dbHandles, db);

                                                    dbh.addStatement(stmtHandle.readPointer().readPointer().toString(), stmt);
                                                    console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                    console.log('\tDB: "' + dbh.filename + '"');
                                                    console.log('\tSQL: "' + stmt + '"');
                                                }
                                            }
                                        });
                                    } catch (error) {
                                        console.error('\x1b[31m[!] Error: ' + error + '\x1b[0m]');
                                    }
                                    break;
                                case "sqlite3_prepare16_v3":
                                    console.log('[+] Hooking: ' + e.name + ' @ 0x' + functionAddr.toString(16));
                                    try {
                                        var db;
                                        var stmt;
                                        var stmtHandle;
                                        Interceptor.attach(functionAddr, {
                                            onEnter: function (args) {
                                                db = args[0].readPointer().toString();
                                                stmt = Memory.readUtf16String(args[1]);
                                                stmtHandle = args[4];
                                            },
                                            onLeave: function (retvalue) {
                                                if (stmt != "BEGIN ") {
                                                    var dbh = sqliteObject.find(dbHandles, db);

                                                    dbh.addStatement(stmtHandle.readPointer().readPointer().toString(), stmt);
                                                    console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                    console.log('\tDB: "' + dbh.filename + '"');
                                                    console.log('\tSQL: "' + stmt + '"');
                                                }
                                            }
                                        });
                                    } catch (error) {
                                        console.error('\x1b[31m[!] Error: ' + error + '\x1b[0m]');
                                    }
                                    break;
                                case "sqlite3_load_extension":
                                    console.log('[+] Hooking: ' + e.name + ' @ 0x' + functionAddr.toString(16));
                                    try {
                                        Interceptor.attach(functionAddr, {
                                            onEnter: function (args) {
                                                var dbhName = args[0].readPointer().toString();
                                                var dbh = sqliteObject.find(dbHandles, dbhName);
                                                console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                console.log('\tDB: "' + (dbh ? dbh.filename : dbhName) + '"');
                                                console.log('\tExtension: "' + Memory.readUtf8String(args[1]) + '"');
                                            },
                                            onLeave: function (retvalue) {
                                            }
                                        });
                                    } catch (error) {
                                        console.error('\x1b[31m[!] Error: ' + error + '\x1b[0m]');
                                    }
                                    break;
                                case "sqlite3_bind_parameter_count":
                                    console.log('[+] Hooking: ' + e.name + ' @ 0x' + functionAddr.toString(16));
                                    try {
                                        Interceptor.attach(functionAddr, {
                                            onEnter: function (args) {
                                                this.stmtHandle = args[0].readPointer().toString();
                                            },
                                            onLeave: function (retvalue) {
                                                var dbh = sqliteObject.getDbByStatementHandle(dbHandles, this.stmtHandle);
                                                if (dbh) {
                                                    var stmtIdx = dbh.getStatementIndex(this.stmtHandle);
                                                    dbh.statement[stmtIdx].argCount = retvalue.toInt32();
                                                    console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                    console.log('\tArg Count: ' + retvalue);
                                                    console.log('\tDB: "' + dbh.filename + '"');
                                                    console.log('\tSQL: "' + dbh.statement[stmtIdx].sql + '"');

                                                    try {
                                                        if (dbh.statement[stmtIdx].argCount == Object.keys(dbh.statement[stmtIdx].arguments).length) {
                                                            var sqlArgs = dbh.getStatementArguments(stmtIdx);
                                                            for (var i in sqlArgs) {
                                                                console.log('\t\tArg : ' + i + ' => ' + sqlArgs[i]);
                                                            }
                                                        }
                                                    } catch { }
                                                } else {
                                                    console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                    console.log('\tunable to locate statement handle ' + stmtHandle);
                                                }
                                            }
                                        });
                                    } catch (error) {
                                        console.error('\x1b[31m[!] Error: ' + error + '\x1b[0m]');
                                    }
                                    break;
                                case "sqlite3_bind_blob":
                                case "sqlite3_bind_blob64":
                                case "sqlite3_bind_double":
                                case "sqlite3_bind_int":
                                case "sqlite3_bind_int64":
                                case "sqlite3_bind_text16":
                                case "sqlite3_bind_text64":
                                case "sqlite3_bind_value":
                                case "sqlite3_bind_pointer":
                                case "sqlite3_bind_zeroblob":
                                case "sqlite3_bind_zeroblob64":
                                case "sqlite3_bind_text":
                                    console.log('[+] Hooking: ' + e.name + ' @ 0x' + functionAddr.toString(16));
                                    try {
                                        Interceptor.attach(functionAddr, {
                                            onEnter: function (args) {
                                                var stmtHandle = args[0].readPointer().toString();
                                                var paramIndex = args[1].toInt32();
                                                var value;
                                                if (e.name === "sqlite3_bind_text") {
                                                    value = Memory.readUtf8String(args[2]);
                                                } else {
                                                    value = '[' + e.name.slice(13).toUpperCase() + ' Object]';
                                                }

                                                var dbh = sqliteObject.getDbByStatementHandle(dbHandles, stmtHandle);
                                                if (dbh) {
                                                    var stmtIdx = dbh.getStatementIndex(stmtHandle);
                                                    dbh.addStatementArgument(stmtHandle, value, paramIndex);
                                                    console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                    console.log('\tDB: "' + dbh.filename + '"');
                                                    console.log('\tSQL: "' + dbh.statement[stmtIdx].sql + '"');

                                                    try {
                                                        if (dbh.statement[stmtIdx].argCount == Object.keys(dbh.statement[stmtIdx].arguments).length) {
                                                            var sqlArgs = dbh.getStatementArguments(stmtIdx);
                                                            for (var i in sqlArgs) {
                                                                console.log("\t\tArg : " + i + " => " + sqlArgs[i]);
                                                            }
                                                        }
                                                    } catch { }
                                                }
                                                else {
                                                    console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                    console.log('\tunable to locate statement handle ' + stmtHandle);
                                                }

                                            },
                                            onLeave: function (retvalue) {
                                            }
                                        });
                                    } catch (error) {
                                        console.error('\x1b[31m[!] Error: ' + error + '\x1b[0m]');
                                    }
                                    break;
                                case "sqlite3_exec":
                                    console.log('[+] Hooking: ' + e.name + ' @ 0x' + functionAddr.toString(16));
                                    try {
                                        Interceptor.attach(functionAddr, {
                                            onEnter: function (args) {
                                                var dbhName = args[0].readPointer().toString();
                                                var dbh = sqliteObject.find(dbHandles, dbhName);
                                                console.log('\x1b[36m[' + e.name + ']\x1b[0m');
                                                console.log('\tDB: "' + (dbh ? dbh.filename : dbhName) + '"');
                                                console.log('\tSQL: ' + Memory.readUtf8String(args[1]));
                                            },
                                            onLeave: function (retvalue) {
                                            }
                                        });
                                    } catch (error) {
                                        console.error('\x1b[31m[!] Error: ' + error + '\x1b[0m]');
                                    }
                                    break;

                                default:
                                    if (hookAll) {
                                        console.log('[+] Hooking: ' + e.name + ' @ 0x' + functionAddr.toString(16));
                                        try {
                                            Interceptor.attach(functionAddr, {
                                                onEnter: function (args) {
                                                    console.log('\x1b[32m[' + e.name + ']\x1b[0m \tEnter');
                                                },
                                                onLeave: function (retvalue) {
                                                }
                                            });
                                        } catch (error) {
                                            console.error('\x1b[31m[!] [' + e.name + '] ' + error + '\x1b[0m]');
                                        }
                                    }
                                    break;
                            }
                        } else {
                            console.log('[!] Unable to locate function ' + e.name);
                        }
                    },
                    onComplete: function () {
                        console.log('[+] Finished hooking module');
                    }
                });
            }
        },
        onComplete: function () { }
    });
})();
