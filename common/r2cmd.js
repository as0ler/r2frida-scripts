'use strict';


const commands = {
  'r2cmd': r2cmd
};
  
r2frida.pluginRegister('r2cmd', function (name) {
  return commands[name];
});

function r2cmd(args) {
  return new Promise((resolve, reject) => {
    try {
      r2frida
        .hostCmd('?E hello from r2')
        .then(res => {
          resolve(res);
        });
    } catch(e) {
        console.error(e);
        reject(e);
    }
  });
}
