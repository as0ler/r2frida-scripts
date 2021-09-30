'use strict';

const commands = {
  'hello': hello
};

r2frida.pluginRegister('hello', function (name) {
  return commands[name];
});

const ObjCAvailable = (Process.platform === 'darwin') && ObjC && ObjC.available && ObjC.classes && typeof ObjC.classes.NSString !== 'undefined';

async function hello(args) {
 if (!ObjCAvailable) {
    return 'Error: Not implemented for this platform';
  }
  const title = 'r2con 2021';
  const message = 'Hello r2con!' 
  ObjC.schedule(ObjC.mainQueue, function () {
    const UIAlertView = ObjC.classes.UIAlertView; /* iOS 7 */
    const view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(
      title,
      message,
      NULL,
      'OK',
      NULL);
    view.show();
    view.release();
  });
}
