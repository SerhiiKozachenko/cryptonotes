# cryptonotes

CLI tool to encrypt/decrypt text, files, and directories.


## Usage

Download binary

    $ curl -L https://github.com/SerhiiKozachenko/cryptonotes/releases/latest/download/cryptonotes-mac-aarch64 > cryptonotes && chmod +x cryptonotes

Encrypt directory, will encrypt and rename all sub-directories and files with encrypted names.

    $ cryptonotes encrypt-dir ./my-private my-password-123
    
Decrypt directory, will decrypt and rename all sub-directories and files with their original names.

    $ cryptonotes decrypt-dir ./my-private my-password-123

## Options

    $ cryptonotes {command} {path/text} {password}


## License

Copyright © 2023 Serhii Kozachenko

Distributed under the Eclipse Public License, the same as Clojure.

This program and the accompanying materials are made available under the
terms of the Eclipse Public License 2.0 which is available at
http://www.eclipse.org/legal/epl-2.0.
