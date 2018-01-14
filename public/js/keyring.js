/**
 * @file KeyRing is an encrypted JSON store built on Firebase, intended for
 *       use as a password management application. Encryption and decryption is
 *       entirely client-side; passwords and keys generated from them are not
 *       stored in Firebase. KeyRing is written around asmcrypto.js, especially
 *       its implementation of AES-GCM and SHA256. Use only with HTTPS, or
 *       there's not much point to the secrecy! Only works in modern browsers,
 *       because the application makes heavy use of TypedArrays.
 * @author Connor Wiseman
 * {@link https://github.com/vibornoff/asmcrypto.js}
 * @todo Polyfill TypedArrays?
 */

/**
 * A self-invoking anonymous function expression that encapsulates potentially
 * sensitive data being exchanged between the client and Firebase and isolates
 * it from other scripts being concurrently executed in the browser. It's a
 * security pattern, essentially, because the global scope can't readily access
 * any of the information being worked on by the local scope; it prevents the
 * client's plaintext information from leaking via JavaScript.
 * @param  {Object} window    A reference to the global window object.
 * @param  {Object} document  A reference to window.document.
 * @param  {Object} undefined
 * @public
 */
(function(window, document, undefined) {
  'use strict';

  /**
   * Firebase configuration. Edit accordingly if you've cloned KeyRing and are
   * running your own instance of the application.
   * @type {Object}
   * @private
   */
  var config = {
    apiKey:            "AIzaSyAsx3AFPhyPI3s_HsWwOTm9UxmmB6nugTQ",
    authDomain:        "keyring-demo.firebaseapp.com",
    databaseURL:       "https://keyring-demo.firebaseio.com",
    projectId:         "keyring-demo",
    storageBucket:     "",
    messagingSenderId: "940586750921"
  };

  // Ensure connections to Firebase are secure. This is not negotiable!
  if (config.databaseURL.split('://')[0] !== 'https') {
    throw new Error('Connections to Firebase must be secure.');
  }

  // Check the current protocol and issue a warning if it's not HTTPS.
  if (window.location.protocol !== 'https:') {
    console.warn('You are not browsing via HTTPS. All connections to Firebase are encrypted; however, your local data is not fully protected on the client-side.');
  }

  // Initialize the Firebase application.
  firebase.initializeApp(config);

  /**
   * Decrypts the specified content using the specified key and nonce values.
   * Utilizes the AES-GCM algorithm for decryption. Nonce is the term that
   * asmcrypto.js uses to refer to an initialization vector.
   * @param  {Uint8Array} encrypted
   * @param  {Uint8Array} key
   * @param  {Uint8Array} nonce
   * @return {Uint8Array}
   * @private
   */
  function aesDecrypt(encrypted, key, nonce) {
    return asmCrypto.AES_GCM.decrypt(encrypted, key, nonce, undefined, 16);
  };

  /**
   * Encrypts the specified content using the specified key and nonce values.
   * Utilizes the AES-GCM algorithm for encryption. Nonce is the term that
   * asmcrypto.js uses to refer to an initialization vector.
   * @param  {String}     plaintext
   * @param  {Uint8Array} key
   * @param  {Uint8Array} nonce
   * @return {Uint8Array}
   * @private
   */
  function aesEncrypt(plaintext, key, nonce) {
    return asmCrypto.AES_GCM.encrypt(plaintext, key, nonce, undefined, 16);
  };

  /**
   * Returns a compatible JSON object as a Uint8Array.
   * @param  {Object} obj A JSON interpretation of a Uint8Array.
   * @return {Uint8Array}
   * @private
   */
  function jsonObjToTypedArray(obj) {
    var length = Object.keys(obj).length,
        arr = new Uint8Array(length);
    for (var i = 0; i < length; i++) {
      arr[i] = obj[i];
    }
    return arr;
  };

  /**
   * @namespace KeyRing
   */

  /**
   * A collection of functions for encrypting/decrypting data and performing
   * various transforms from one data type to another. Makes heavy use of
   * asmcrypto.js's function set.
   * @type {Object}
   * @private
   */
  var KeyRing = {};

  /**
   * Decrypts a specially-formatted data object of JSON strings, which is just
   * an object that has two keys, `nonce` and `contents`, both of which are
   * Uint8Arrays. `contents` is what is actually decrypted using the specified
   * key. The nonce value for the decryption is borrowed from the object's own
   * `nonce` property, which assuredly must exist because it's added to the
   * object returned via initial encryption if it doesn't already exist. The
   * `contents` themselves are a JSON-encoded Uint8Array, so after they're
   * reconstituted in a format that asmcrypto can digest the algorithm is
   * completed by decrypting, then JSON parsing the `contents` and returning
   * the newly reconstructed data object.
   * @param  {Object}     data
   * @param  {Uint8Array} key
   * @return {String}
   * @memberof KeyRing
   * @public
   */
  KeyRing.decrypt = function decrypt(data, key) {
    if (data === null) {
      return {
        contents: {}
      };
    }

    var obj = Object.assign({}, {
      nonce: jsonObjToTypedArray(JSON.parse(data.nonce)),
      contents: jsonObjToTypedArray(JSON.parse(data.contents))
    });
    var decr = aesDecrypt(obj.contents, key, obj.nonce);
    obj.contents = JSON.parse(String.fromCharCode.apply(null, decr));
    console.log(obj);
    return obj;
  };

  /**
   * The properties permitted in data objects. `contents` could theoretically
   * include anything, but for the purposes of this application, data objects
   * are only allowed to contain the following direct child properties.
   * @type {Array}
   * @private
   */
  const allowedProperties = ['nonce', 'contents'];

  /**
   * Encrypts a specially-formated data object, or an object that has two keys,
   * `nonce` and `contents`, both of which are Uint8Arrays. `contents` is what
   * is actually encrypted using the specified key. The nonce value for the
   * encryption is borrowed from the object's own `nonce` property. The
   * `contents` themselves are JSON-encoded prior to encryption. Extraneous
   * properties are stripped from the data object prior to storage to decrease
   * the amount of data stored and transmitted.
   * @param  {Object}     data
   * @param  {Uint8Array} key
   * @return {String}
   * @memberof KeyRing
   * @public
   */
  KeyRing.encrypt = function encrypt(data, key) {
    var obj = Object.assign({}, data);

    // Remove extraneous properties.
    for (var property in obj) {
      if (obj.hasOwnProperty(property) &&
          allowedProperties.indexOf(property) < 0) {
        delete obj.property;
      }
    }

    // Protect against stream cipher attacks and recalculate the nonce.
    obj.nonce = KeyRing.randomValuesArray();
    obj.contents = aesEncrypt(JSON.stringify(obj.contents), key, obj.nonce);
    return obj;
  };

  /**
   * Returns a Uint8Array representation of the SHA256 message digest of a
   * specified string.
   * @param  {String} string
   * @return {Uint8Array}
   * @memberof KeyRing
   * @public
   */
  KeyRing.key = function key(string) {
    return asmCrypto.SHA256.bytes(string);
  };

  /**
   * Returns a Uint8Array of random data, generated by the system PRNG. Does
   * not necessarily have to be cryptographically strong random data; it merely
   * needs to provide relatively unique, difficult-to-replicate data.
   * @param  {Number} [length] The length of the Uint8Array. Defaults to 32.
   * @return {Uint8Array}
   * @memberof KeyRing
   * @public
   */
  KeyRing.randomValuesArray = function randomValuesArray(length) {
    asmCrypto.getRandomValues.allowWeak = false;
    asmCrypto.random.skipSystemRNGWarning = true;
    return asmCrypto.getRandomValues(new Uint8Array(length || 32));
  };

  /**
   * @namespace Firebase
   */

  /**
   * A collection of functions and properties for interacting with Firebase.
   * @type {Object}
   * @private
   */
  var Firebase = {};

  /**
   * A reference to the Firebase database.
   * @type {Se}
   * @memberof Firebase
   * @public
   */
  Firebase.db = firebase.database();

  /**
   * Reads the specified data from the database.
   * @return {Promise}
   * @memberof Firebase
   * @public
   */
  Firebase.read = function read() {
    var uid = firebase.auth().currentUser.uid,
        data = Firebase.db.ref(uid);
    return data.once('value').then(function(snapshot) {
      return Promise.resolve(snapshot.val());
    });
  };

  /**
   * Attempts to create the user specified by the given credentials.
   * @param  {String} email
   * @param  {String} password
   * @return {Promise}
   * @memberof Firebase
   * @public
   */
  Firebase.register = function register(email, password) {
    return firebase.auth().createUserWithEmailAndPassword(email, password);
  };

  /**
   * Attempts to authorize the user specified by the credentials provided.
   * @param  {String} email
   * @param  {String} password
   * @return {Promise}
   * @memberof Firebase
   * @public
   */
  Firebase.signIn = function signIn(email, password) {
    return firebase.auth().signInWithEmailAndPassword(email, password);
  };

  /**
   * Attempts to deauthorize the currently authorized user.
   * @return {Promise}
   * @memberof Firebase
   * @public
   */
  Firebase.signOut = function signOut() {
    return firebase.auth().signOut();
  };

  /**
   * Writes the specified data to the database.
   * @param  {*}          data
   * @return {Promise}
   * @memberof Firebase
   * @public
   */
  Firebase.write = function write(data) {
    var uid = firebase.auth().currentUser.uid,
        json = JSON.stringify(data);
    return Firebase.db.ref(uid).set({
      nonce: JSON.stringify(data.nonce),
      contents: JSON.stringify(data.contents)
    });
  };

  /**
   * @namespace Ui
   */

  /**
   * A collection of functions for creating and handling interactions with the
   * various components of KeyRing's user interface.
   * @type {Object}
   * @private
   */
  var Ui = {};

  /**
   * Appends an error notification to the UI contents.
   * @param {String} error
   * @memberof UI
   * @public
   */
  Ui.appendError = function appendError(error) {
    var content = document.getElementById('content'),
        div = document.createElement('div'),
        p = document.createElement('p');
    div.classList.add('error');
    p.appendChild(document.createTextNode(error));
    div.appendChild(p);
    content.appendChild(div);
  };

  /**
   * Populates the Ui's data form with the values decrypted from the database.
   * @param  {Object} data
   * @memberof UI
   * @public
   */
  Ui.populateData = function populateData(data) {
    var contents = document.getElementById('data-contents');

    if (Object.keys(data.contents).length === 0) {
      var p = document.createElement('p');
      p.classList.add('notice');
      p.appendChild(document.createTextNode('You have no data in storage.'));
      contents.appendChild(p);
      return;
    }

    var frag = document.createDocumentFragment();

    for (var group in data.contents) {
      if (data.contents.hasOwnProperty(group)) {
        Ui.addContentGroup(frag, group, data);
      }
    }
    Ui.replaceChildren(contents, frag);
  };

  /**
   * Appends a data content group to the specified UI data form widget.
   * @param  {HTMLElement} parent
   * @param  {String}      name
   * @param  {Object}      data
   * @memberof UI
   * @public
   */
  Ui.addContentGroup = function addContentGroup(parent, name, data) {
    var groupDiv = document.createElement('div'),
        groupHeading = document.createElement('h2'),
        groupContents = document.createElement('dl'),
        groupMenuLink = document.createElement('a'),
        groupMenu = document.createElement('ul');

    var add = document.createElement('li'),
        remove = document.createElement('li');
    add.appendChild(document.createTextNode('Add Key/Value Pair'));
    add.addEventListener('click', function(e) {
      Ui.addKeyValuePair(groupContents, data, '', '');
    });
    remove.appendChild(document.createTextNode('Remove Group'));
    remove.addEventListener('click', function(e) {
      e.preventDefault();
      delete data.contents[groupHeading.innerText];
      groupDiv.parentElement.removeChild(groupDiv);
    });
    groupMenu.appendChild(add);
    groupMenu.appendChild(remove);
    groupMenu.classList.add('menu');
    groupMenuLink.setAttribute('href', '#');
    groupMenuLink.classList.add('menu-link', 'icon-ellipsis-v');
    groupMenuLink.addEventListener('click', function(e) {
      e.preventDefault();
      groupMenu.classList.toggle('menu-visible');
    });
    document.addEventListener('click', function(e) {
      if (e.target !== groupMenuLink) {
          groupMenu.classList.remove('menu-visible');
      };
    });
    groupHeading.appendChild(document.createTextNode(name));
    groupHeading.appendChild(groupMenuLink);
    groupDiv.classList.add('data');
    groupDiv.appendChild(groupHeading);
    groupDiv.appendChild(groupMenu);

    for (var key in data.contents[name]) {
      if (data.contents[name].hasOwnProperty(key)) {
        Ui.addKeyValuePair(groupContents, data, key, data.contents[name][key]);
      }
    }

    groupDiv.appendChild(groupContents);
    parent.appendChild(groupDiv);
  };

  /**
   * Appends a key/value input pair to the specified UI data form widget.
   * @param  {HTMLElement} parent
   * @param  {Object}      data
   * @param  {String}      key
   * @param  {String}      value
   * @memberof UI
   * @public
   */
  Ui.addKeyValuePair = function addKeyValuePair(parent, data, key, value) {
    var keyWrap  = document.createElement('dt'),
        keyLabel = document.createElement('label'),
        keySpan  = document.createElement('span'),
        keyInput = document.createElement('input'),
        valWrap  = document.createElement('dd'),
        valLabel = document.createElement('label'),
        valSpan  = document.createElement('span'),
        valInput = document.createElement('input'),
        delLink  = document.createElement('a');

    keySpan.appendChild(document.createTextNode('Key: '));
    keyInput.classList.add('input', 'input-wide', 'data-key');
    keyInput.setAttribute('value', key);
    keyInput.setAttribute('placeholder', 'Key');
    keyLabel.appendChild(keySpan);
    keyLabel.appendChild(keyInput);
    keyWrap.appendChild(keyLabel);
    valSpan.appendChild(document.createTextNode('Value: '));
    valInput.classList.add('input', 'input-wide', 'data-val');
    valInput.setAttribute('value', value);
    valInput.setAttribute('placeholder', 'Value');
    valLabel.appendChild(valSpan);
    valLabel.appendChild(valInput);
    delLink.setAttribute('href', '#');
    delLink.classList.add('delete-this', 'icon-minus-square-o');
    delLink.addEventListener('click', function(e) {
      e.preventDefault();
      var dd = this.parentElement.parentElement,
          dt = dd.previousElementSibling,
          dl = dd.parentElement,
          h2 = dl.previousElementSibling.previousElementSibling.innerText,
          key = dt.firstElementChild.lastElementChild.value;
      delete data.contents[h2][key];
      dl.removeChild(dt);
      dl.removeChild(dd);
    });
    valLabel.appendChild(delLink);
    valWrap.appendChild(valLabel);
    parent.appendChild(keyWrap);
    parent.appendChild(valWrap);
  };

  /**
   * Creates a UI data form widget.
   * @param  {Object}     data
   * @param  {Uint8Array} key
   * @return {DocumentFragment}
   * @memberof UI
   * @public
   */
  Ui.createDataForm = function createDataForm(data, key) {
    var frag = document.createDocumentFragment(),
        div = document.createElement('div');

    var addForm = document.createElement('form'),
        addInput = document.createElement('input'),
        addButton = document.createElement('button'),
        contentsForm = document.createElement('form');

    addInput.classList.add('input', 'input-wide');
    addInput.setAttribute('maxlength', '32');
    addInput.setAttribute('placeholder', 'Data Group');
    addInput.setAttribute('required', 'required');
    addButton.classList.add('button-green', 'button-small', 'right');
    addButton.appendChild(document.createTextNode('Add'));
    addForm.setAttribute('autocomplete', 'off');
    addForm.setAttribute('autocorrect', 'off');
    addForm.setAttribute('autocapitalize', 'off');
    addForm.setAttribute('spellcheck', 'false');
    addForm.addEventListener('submit', function(e) {
      e.preventDefault();
      addButton.setAttribute('disabled', 'disabled');
      data.contents[addInput.value] = data.contents[addInput.value] || {};
      addForm.reset();
      Ui.populateData(data);
      addButton.removeAttribute('disabled');
    });

    addForm.appendChild(addInput);
    addForm.appendChild(addButton);
    contentsForm.setAttribute('id', 'data-contents');
    contentsForm.setAttribute('autocomplete', 'off');
    contentsForm.setAttribute('autocorrect', 'off');
    contentsForm.setAttribute('autocapitalize', 'off');
    contentsForm.setAttribute('spellcheck', 'false');
    frag.appendChild(addForm);
    frag.appendChild(contentsForm);

    var sync = document.createElement('button');
    sync.classList.add('button-red', 'button-wide');
    sync.appendChild(document.createTextNode('Encrypt & Sync Data'));
    sync.addEventListener('click', function(e) {
      e.preventDefault();
      var dataGroups = document.getElementsByClassName('data');

      for (var i = 0; i < dataGroups.length; i++) {
        var groupName = dataGroups[i].firstElementChild.innerText,
            keys = dataGroups[i].getElementsByClassName('data-key'),
            vals = dataGroups[i].getElementsByClassName('data-val');
        if (keys.length) {
          data.contents[groupName] = {};
        }
        for (var j = 0; j < keys.length; j++) {
          if (keys[j].value !== '') {
            data.contents[groupName][keys[j].value] = vals[j].value;
          }
        }
      }

      Ui.setContents(Ui.createSpinner('Encrypting data...'), 0).then(function() {
        var encr = KeyRing.encrypt(data, key);
        Ui.setContents(Ui.createSpinner('Saving encrypted data...')).then(function() {
          return Firebase.write(encr);
        }).then(function() {
          return Ui.setContents(Ui.createSpinner('Data encrypted and saved!')).then(function() {
            return new Promise(function(resolve, reject) {
                setTimeout(function() {
                  resolve();
                }, 750);
            });
          });
        }).then(function() {
          return Ui.setContents(Ui.createDataForm(data, key));
        }).then(function() {
          Ui.populateData(data);
        });
      });
    });
    frag.appendChild(sync);
    return frag;
  };

  /**
   * Creates a UI register form widget.
   * @return {DocumentFragment}
   * @memberof UI
   * @public
   */
  Ui.createRegisterForm = function createRegisterForm() {
    var frag = document.createDocumentFragment(),
        form = document.createElement('form'),
        p = document.createElement('p'),
        registerButton = document.createElement('button'),
        cancelButton = document.createElement('button');

    p.classList.add('notice');
    p.appendChild(document.createTextNode('No user account with the specified email address currently exists in the database. Would you like to register a new account?'));
    registerButton.classList.add('button-red');
    registerButton.setAttribute('id', 'register');
    registerButton.appendChild(document.createTextNode('Register'));
    cancelButton.classList.add('button-red');
    cancelButton.appendChild(document.createTextNode('Nevermind!'));
    cancelButton.addEventListener('click', function(e) {
      e.preventDefault();
      cancelButton.setAttribute('disabled', 'disabled');
      Ui.setContents(Ui.createSignInForm());
    });

    form.addEventListener('submit', function(e) {
      e.preventDefault();
    });
    form.appendChild(p);
    form.appendChild(registerButton);
    form.appendChild(cancelButton);
    frag.appendChild(form);
    return frag;
  };

  /**
   * Creates a UI sign in form widget.
   * @return {DocumentFragment}
   * @memberof UI
   * @public
   */
  Ui.createSignInForm = function createSignInForm() {
    var frag = document.createDocumentFragment(),
        form = document.createElement('form');
    form.setAttribute('autocomplete', 'off');
    form.setAttribute('autocorrect', 'off');
    form.setAttribute('autocapitalize', 'off');
    form.setAttribute('spellcheck', 'false');

    var emailLabel = document.createElement('label'),
        emailSpan = document.createElement('span'),
        emailInput = document.createElement('input');
    emailSpan.appendChild(document.createTextNode('Email: '));
    emailInput.setAttribute('id', 'email');
    emailInput.setAttribute('type', 'email');
    emailInput.setAttribute('placeholder', 'Email');
    emailInput.setAttribute('required', 'required');
    emailInput.classList.add('input');
    emailLabel.appendChild(emailSpan);
    emailLabel.appendChild(emailInput);
    form.appendChild(emailLabel);

    var passwordLabel = document.createElement('label'),
        passwordSpan = document.createElement('span'),
        passwordInput = document.createElement('input');
    passwordSpan.appendChild(document.createTextNode('Password: '));
    passwordInput.setAttribute('id', 'password');
    passwordInput.setAttribute('type', 'password');
    passwordInput.setAttribute('placeholder', 'Password');
    passwordInput.setAttribute('required', 'required');
    passwordInput.setAttribute('pattern', '.{8,}');
    passwordInput.classList.add('input');
    passwordInput.addEventListener('keyup', function(e) {
      if (passwordInput.validity.patternMismatch) {
        passwordInput.setCustomValidity('Passwords must be at least 8 characters long.');
      } else {
        passwordInput.setCustomValidity('');
      }
    });
    passwordLabel.appendChild(passwordSpan);
    passwordLabel.appendChild(passwordInput);
    form.appendChild(passwordLabel);

    var button = document.createElement('button');
    button.classList.add('button-red');
    button.appendChild(document.createTextNode('Sign In'));
    form.appendChild(button);

    form.addEventListener('submit', function(e) {
      e.preventDefault();
      var email = document.getElementById('email').value,
          password = document.getElementById('password').value,
          key, data;

      button.setAttribute('disabled', 'disabled');

      function processAuthorization(authPromise) {
        authPromise.then(function() {
          return Ui.setContents(Ui.createSpinner('Retrieving encrypted data...'));
        }).then(function() {
          var uid = firebase.auth().currentUser.uid;
          key = KeyRing.key(uid + email + password);
          return Firebase.read();
        }).then(function(result) {
          data = result;
          return Ui.setContents(Ui.createSpinner('Decrypting data...'));
        }).then(function() {
          data = KeyRing.decrypt(data, key);
          return Ui.setContents(Ui.createDataForm(data, key));
        }).then(function() {
          Ui.populateData(data);
        });
      };

      Ui.setContents(Ui.createSpinner('Signing in...', 0)).then(function() {
        var auth = Firebase.signIn(email, password).then(function() {
          return processAuthorization(auth);
        }).catch(function(error) {
          if (error.code === 'auth/user-not-found') {
            Ui.setContents(Ui.createRegisterForm()).then(function() {
              document.getElementById('register').addEventListener('click', function(e) {
                e.preventDefault();
                this.setAttribute('disabled', 'disabled');
                Ui.setContents(Ui.createSpinner('Registering...', 0)).then(function() {
                  return processAuthorization(Firebase.register(email, password));
                });
              });
            });
          } else {
            Ui.setContents(Ui.createSignInForm()).then(function() {
              Ui.appendError(error);
            });
          }
        });
      });
    });

    frag.appendChild(form);
    return frag;
  };

  /**
   * Creates a UI spinner widget.
   * @return {DocumentFragment}
   * @memberof UI
   * @public
   */
  Ui.createSpinner = function createSpinner(text) {
    var frag = document.createDocumentFragment(),
        container = document.createElement('div');
    container.setAttribute('id', 'spinner');
    for (var i = 1; i < 6; i++) {
      var div = document.createElement('div');
      div.classList.add('rect' + i);
      container.appendChild(div);
    }
    var p = document.createElement('p');
    p.setAttribute('id', 'spinner-text');
    p.appendChild(document.createTextNode(text || ''));
    container.appendChild(p);
    frag.appendChild(container);
    return frag;
  };

  /**
   * Removes all the children of the specified HTMLElement object and replaces
   * them with the specified new child node. The new child node may be another
   * HTMLElement, a DocumentFragment, and so on.
   * @param  {HTMLElement} parent
   * @param  {Node}        newChild
   * @return {HTMLElement}
   * @memberof Ui
   * @public
   */
  Ui.replaceChildren = function replaceChildren(parent, newChild) {
    while (parent.firstChild) {
      parent.removeChild(parent.firstChild);
    }
    parent.appendChild(newChild);
    return parent;
  };

  /**
   * Sets the contents of the UI. If the optional delay flag is present and is
   * set to false (as in, /don't/ delay), the fading animation via classList
   * manipulation won't be triggered and the returned Promise will resolve
   * immediately. Otherwise, there's a brief delay during which the UI is
   * fading old content out and fading new content in.
   * @param  {DocumentFragment} fragment
   * @param  {Number}          [delay]
   * @return {Promise}
   * @memberof UI
   * @public
   */
  Ui.setContents = function setContents(fragment, delay) {
    return new Promise(function(resolve, reject) {
      var content = document.getElementById('content'),
          timeDelay = delay || 250;

      setTimeout(function() {
        content.classList.add('fade');
        setTimeout(function() {
          content.classList.remove('fade');
          Ui.replaceChildren(content, fragment);
          resolve();
        }, timeDelay);
      }, timeDelay);
    });
  };

  // Once the page has loaded, display the appropriate UI elements.
  document.addEventListener('DOMContentLoaded', function(e) {
    Ui.setContents(Ui.createSpinner('Building Ui...'), 0).then(function() {
      return Ui.setContents(Ui.createSignInForm());
    });
  });

  // Make a cursory attempt to deauthorize the user when the page is unloaded.
  window.addEventListener('unload', function(e) {
    Firebase.signOut();
  });

})(window, window.document);
