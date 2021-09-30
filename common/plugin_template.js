'use strict';

const commands = {
  'example': example_func
};

r2frida.pluginRegister('example', function (name) {
  return commands[name];
});

async function example_func(args) {
	return args[0];  
}
