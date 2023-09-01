(ns cryptonotes.core-test
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer :all]
            [cryptonotes.core :refer :all]))

(deftest encrypt-decrypt-text
  (testing "Can encrypt/decrypt text"
    (let [secret "my super secret"
          pass "mypass123"
          secret-enc (encrypt-text secret pass)
          secret-dec (decrypt-text secret-enc pass)]
      (is (not (str/blank? secret-enc)))
      (is (not= secret-enc secret))
      (is (= secret-dec secret))))

  (testing "Can encrypt/decrypt multi-line text with special chars"
    (let [secret "my super secret on a few lines
    line 2
    line 3
    line 4
    !@#$%^&*()+_?>Z±|~"
          pass "mypass123"
          secret-enc (encrypt-text secret pass)
          secret-dec (decrypt-text secret-enc pass)]
      (is (not (str/blank? secret-enc)))
      (is (not= secret-enc secret))
      (is (= secret-dec secret)))))

(deftest encrypt-decrypt-file
  (testing "Can encrypt/decrypt file"
    (let [file "private/MySecrets/README.MD"
          pass "mypass123"
          ;; encrypted file name
          file-enc "private/MySecrets/WHJp18ZhXYTQghLBh99svHwIYQrJA0fkwQ=="]
      ;; encrypted successfully, can throw
      (is (true? (encrypt-file! file pass)))
      ;; orig file was deleted
      (is (false? (.exists (io/file file))))
      ;; decrypted successfully, can throw
      (is (true? (decrypt-file! file-enc pass)))
      ;; encrypted file was deleted
      (is (false? (.exists (io/file file-enc)))))))

(deftest encrypt-decrypt-dir
  (testing "Can encrypt/decrypt directory"
    (let [root-dir "private"
          file-in-dir "private/MySecrets/README.MD"
          pass "mypass123"
          ;; encrypted file name
          file-in-dir-enc "private/R0579uhWFr3nM7MBKLWcEbr50ubZpas9XQ==/WHJp18ZhXYTQghLBh99svHwIYQrJA0fkwQ=="]
      ;; encrypted successfully, can throw
      (encrypt-dir! root-dir pass)
      ;; orig file was deleted
      (is (false? (.exists (io/file file-in-dir))))
      ;; encrypted file exists
      (is (true? (.exists (io/file file-in-dir-enc))))
      ;; decrypted successfully, can throw
      (decrypt-dir! root-dir pass)
      ;; encrypted file was deleted
      (is (false? (.exists (io/file file-in-dir-enc))))
      ;; decrypted file exists
      (is (true? (.exists (io/file file-in-dir)))))))
