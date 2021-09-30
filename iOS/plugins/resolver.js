'use strict';

r2frida.pluginRegister('resolver', function (commandName) {
    if (commandName === 'find') {
        return function (args) {
            var query = args.join(' ');
            return new ApiResolver('objc').enumerateMatchesSync(query)
            .map(function (match) {
                return match.address + '\t' + match.name;
            }).join('\n');
        }
    }
});