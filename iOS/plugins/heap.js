'use strict';

r2frida.pluginRegister('heap', function (commandName) {
    if (commandName === 'choose') {
        return function (args) {
            var query = ObjC.classes[args[0]];
            return ObjC.chooseSync(query)
            .map(function (match) {
                return match;
            }).join('\n');
        }
    }
});