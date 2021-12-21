/*
 * r2frida Plugin based on https://codeshare.frida.re/@dki/ios-url-scheme-fuzzing/
 *
 * iOS URL Scheme Fuzzing
 *
 */

var fuzzStrings = ["0",
    "1",
    "-1",
    "null",
    "nil",
    "99999999999999999999999999999999999",
    Array(257).join("A"),
    Array(1026).join("A"),
    "'",
    "%20d",
    "%20n",
    "%20x",
    "%20s"
];

const commands = {
    fuzz: fuzz,
    openURL: openURL,
    bundleExecutableForScheme: bundleExecutableForScheme
  };

r2frida.pluginRegister('schema_fuzz', function (name) {
return commands[name];
});

function openURL(args) {
    return _openURL(args[0]);
}

function bundleExecutableForScheme(args) {
    return _bundleExecutableForScheme(args[0]);
}

function _openURL(url) {
    var w = ObjC.classes.LSApplicationWorkspace.defaultWorkspace();
    var toOpen = ObjC.classes.NSURL.URLWithString_(url);
    return w.openSensitiveURL_withOptions_(toOpen, null);
}

function _bundleExecutableForScheme(scheme) {  
    var apps = ObjC.classes.LSApplicationWorkspace.defaultWorkspace().applicationsAvailableForHandlingURLScheme_(scheme);
    console.log(apps);
    if (apps.count() != 1) {
        return null;
    }

    var appProxy = apps.objectAtIndex_(0); // LSApplicationProxy
    var bundleExecutable = appProxy.bundleExecutable();
    if (bundleExecutable !== null) {
        return bundleExecutable.toString();
    }

    return null;
}

function homeSinglePress() {
    ObjC.schedule(ObjC.mainQueue, function() {
        ObjC.classes.SBUIController.sharedInstance().handleHomeButtonSinglePressUp();
    });
}

// https://stackoverflow.com/questions/610406/javascript-equivalent-to-printf-string-format
if (!String.format) {
    String.format = function(format) {
        var args = Array.prototype.slice.call(arguments, 1);
        return format.replace(/{(\d+)}/g, function(match, number) {
            return typeof args[number] != 'undefined' ?
                args[number] :
                match;
        });
    };
}

fuzzStrings.iter = function() {
    var index = 0;
    var data = this;
    return {
        next: function() {
            return {
                value: data[index],
                done: index++ == (data.length - 1)
            };
        },
        hasNext: function() {
            return index < data.length;
        }
    }
};

// check for crash logs and move them to /tmp/ if they exist
function moveCrashLogs(appname) {
    var match = appname + "*.ips";
    var pred = ObjC.classes.NSPredicate.predicateWithFormat_('SELF like "' + match + '"');
    var fm = ObjC.classes.NSFileManager.defaultManager();
    var dirlist = fm.contentsOfDirectoryAtPath_error_("/private/var/mobile/Library/Logs/CrashReporter", NULL);
    var results = dirlist.filteredArrayUsingPredicate_(pred);
    if (results.count() > 0) {
        for (var i = 0; i < results.count(); i++) {
            var src = results.objectAtIndex_(i).toString();
            fm.moveItemAtPath_toPath_error_("/private/var/mobile/Library/Logs/CrashReporter/" + src, "/tmp/" + src, NULL);
			console.log('Crash detected - ' + src);
        }
        return true;
    }
    return false;
}

function fuzz(args) {
    url = args[0];
    var appname = _bundleExecutableForScheme(url.split(':')[0]);
    if (appname === null) {
        console.log("Could not determine which app handles this URL!");
        return;
    }

    function Fuzzer(url, appname, iter) {
        this.url = url;
        this.appname = appname;
        this.iter = iter;
    }

    Fuzzer.prototype.checkForCrash = function(done) {
        homeSinglePress();
        moveCrashLogs(this.appname)
        if (!done) {
            this.fuzz();
        }
    };

    Fuzzer.prototype.fuzz = function() {
        var term = this.iter.next();
        var fuzzedURL = String.format(this.url, term.value);
        if (_openURL(fuzzedURL)) {
            console.log("Opened URL: " + fuzzedURL);
        } else {
            console.log("URL refused by SpringBoard: " + fuzzedURL);
        }
        ObjC.classes.NSThread.sleepForTimeInterval_(3);
        this.checkForCrash(term.done);
    };

    console.log("Watching for crashes from " + appname + "...");

    if (moveCrashLogs(appname)) {
        console.log("Moved one or more logs to /tmp/ before fuzzing!");
    }
    var iter = fuzzStrings.iter();
    var fuzzer = new Fuzzer(url, appname, iter);
    fuzzer.fuzz();
}

