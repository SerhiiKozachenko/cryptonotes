(ns cryptonotes.core
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import (java.io File)
           (java.nio.charset Charset StandardCharsets)
           (java.security MessageDigest)
           (java.security.spec AlgorithmParameterSpec)
           (java.time Instant)
           (java.util Base64)
           (javax.crypto.spec SecretKeySpec)
           (javax.crypto AEADBadTagException Cipher CipherOutputStream SecretKeyFactory)
           (javax.crypto.spec IvParameterSpec PBEKeySpec))
  (:gen-class))

(set! *warn-on-reflection* true)

(def ^AlgorithmParameterSpec nonce
  (IvParameterSpec. (byte-array 12)))                       ; 96-bit IV

;; benchmarks https://medium.com/@gerritjvv/aes-java-encryption-performance-benchmarks-3c2cb19a40e9
;; ChaCha20-Poly1305
;; https://blog.cloudflare.com/do-the-chacha-better-mobile-performance-with-cryptography/

(defn- ^SecretKeySpec generate-secret-key
  ([passphrase] (generate-secret-key passphrase "nosalt"))
  ([^String passphrase ^String salt]
   (let [key-factory (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA256")
         iteration-count 10000
         key-spec (PBEKeySpec. (.toCharArray passphrase)
                               (.getBytes salt StandardCharsets/UTF_8)
                               iteration-count 256)]        ; Key length in bits
     (let [secret-key (.generateSecret key-factory key-spec)]
       (SecretKeySpec. (.getEncoded secret-key) "ChaCha20")))))

(defn- escape-base64 [base64]
  (str/replace base64 #"/" "-"))

(defn- ^String unescape-base64 [base64]
  (str/replace base64 #"-" "/"))

(defn- byte-arrays-equal? [a b]
  (and (= (count a) (count b))
       (empty? (filter (complement zero?) (map bit-xor a b)))))

(defn encrypt-text [^String plain-text passphrase]
  (let [key (generate-secret-key passphrase)
        cipher (Cipher/getInstance "ChaCha20-Poly1305")]
    (.init cipher Cipher/ENCRYPT_MODE key nonce)
    (let [plain-text-bytes (.getBytes plain-text ^Charset StandardCharsets/UTF_8)
          encrypted-bytes (.doFinal cipher plain-text-bytes)
          base64-encoded (.encodeToString (Base64/getEncoder) encrypted-bytes)]
      (escape-base64 base64-encoded))))

(defn decrypt-text [^String encrypted-base64 passphrase]
  (let [key (generate-secret-key passphrase)
        cipher (Cipher/getInstance "ChaCha20-Poly1305")]
    (.init cipher Cipher/DECRYPT_MODE key nonce)
    (let [base64-decoded (.decode (Base64/getDecoder) (unescape-base64 encrypted-base64))]
      (try
        (String. (.doFinal cipher base64-decoded) StandardCharsets/UTF_8)
        (catch AEADBadTagException _
          (throw (ex-info "Failed to decrypt file" {})))))))

(defn- calculate-checksum [file-path]
  (let [digest (MessageDigest/getInstance "MD5")
        buffer (make-array Byte/TYPE 8192)]
    (with-open [input-stream (io/input-stream file-path)]
      (loop []
        (let [n (.read input-stream buffer)]
          (when (not= n -1)
            (.update digest buffer 0 n)
            (recur)))))
    (.digest digest)))

(defn- delete-directory-recursive!
  "Recursively delete a directory."
  [^File file]
  (when (.isDirectory file)
    (run! delete-directory-recursive! (.listFiles file)))
  (io/delete-file file))

(defn- ensure-integrity! [orig-file encrypted-file ^SecretKeySpec key]
  (let [cipher (Cipher/getInstance "ChaCha20-Poly1305")
        temp-file (File/createTempFile (str (.toEpochMilli (Instant/now))) ".tmp")]
    (try
      (.init cipher Cipher/DECRYPT_MODE key nonce)
      (with-open [input-stream (io/input-stream encrypted-file)
                  output-stream (io/output-stream temp-file)
                  decrypted-output-stream (CipherOutputStream. output-stream cipher)]
        (io/copy input-stream decrypted-output-stream))
      (when-not (byte-arrays-equal? (calculate-checksum orig-file)
                                    (calculate-checksum temp-file))
        (throw (Exception. "Checksums do not match")))
      (finally
        (.delete temp-file)))))

(defn encrypt-file!
  ([input-file passphrase]
   (let [file (io/file input-file)
         parent (.getParent file)
         fname-enc (encrypt-text (.getName file) passphrase)
         output-file (if parent
                       (str parent "/" fname-enc)
                       fname-enc)]
     (encrypt-file! input-file passphrase output-file)))
  ([input-file passphrase output-file]
   (let [key (generate-secret-key passphrase)
         cipher (Cipher/getInstance "ChaCha20-Poly1305")]
     (.init cipher Cipher/ENCRYPT_MODE key nonce)
     (with-open [input-stream (io/input-stream input-file)
                 output-stream (io/output-stream output-file)
                 encrypted-output-stream (CipherOutputStream. output-stream cipher)]
       (io/copy input-stream encrypted-output-stream))
     (ensure-integrity! input-file output-file key)
     (.delete (io/file input-file)))))

(defn decrypt-file!
  ([input-file passphrase]
   (let [file (io/file input-file)
         parent (.getParent file)
         fname-dec (decrypt-text (.getName file) passphrase)
         output-file (if parent
                       (str parent "/" fname-dec)
                       fname-dec)]
     (decrypt-file! input-file passphrase output-file)))
  ([input-file passphrase output-file]
   (let [key (generate-secret-key passphrase)
         cipher (Cipher/getInstance "ChaCha20-Poly1305")]
     (.init cipher Cipher/DECRYPT_MODE key nonce)
     (try
       (with-open [input-stream (io/input-stream input-file)
                   output-stream (io/output-stream output-file)
                   decrypted-output-stream (CipherOutputStream. output-stream cipher)]
         (io/copy input-stream decrypted-output-stream))
       (catch AEADBadTagException _
         (throw (ex-info "Failed to decrypt file" {}))))
     (.delete (io/file input-file)))))

(defn encrypt-dir! [path passphrase]
  (let [root (io/file path)
        dir? #(.isDirectory ^File %)
        dirs-to-delete (filter dir? (.listFiles root))]
    (->> (tree-seq dir? #(.listFiles ^File %) root)
         (remove #(= root %))
         (filter (complement dir?))
         (pmap (fn [^File file]
                 ;; file path without root folder
                 (let [fpath (str/replace-first (.getPath file)
                                                (re-pattern path)
                                                "")
                       fpath (if (str/starts-with? fpath "/")
                               (str/replace-first fpath #"/" "")
                               fpath)
                       ;; directory names, drop last is file name
                       fdirs (drop-last (str/split fpath #"/"))
                       fname-enc (encrypt-text (.getName file) passphrase)
                       fdirs-enc (map #(encrypt-text % passphrase) fdirs)
                       fpath-enc (str
                                   (if (str/ends-with? path "/")
                                     path
                                     (str path "/"))
                                   (str/join "/" fdirs-enc))
                       fname-enc (str fpath-enc "/" fname-enc)]

                   (.mkdirs (io/file fpath-enc))
                   (encrypt-file! file passphrase fname-enc))))
         doall)
    ;; delete empty folders
    (run! delete-directory-recursive! dirs-to-delete)))

(defn decrypt-dir! [path passphrase]
  (let [root (io/file path)
        dir? #(.isDirectory ^File %)
        dirs-to-delete (filter dir? (.listFiles root))]
    (->> (tree-seq dir? #(.listFiles ^File %) root)
         (remove #(= root %))
         (filter (complement dir?))
         (pmap (fn [^File file]
                 ;; file path without root folder
                 (let [fpath (str/replace-first (.getPath file)
                                                (re-pattern path)
                                                "")
                       fpath (if (str/starts-with? fpath "/")
                               (str/replace-first fpath #"/" "")
                               fpath)
                       ;; directory names, drop last is file name
                       fdirs (drop-last (str/split fpath #"/"))
                       fname-dec (decrypt-text (.getName file) passphrase)
                       fdirs-dec (map #(decrypt-text % passphrase) fdirs)
                       fpath-dec (str
                                   (if (str/ends-with? path "/")
                                     path
                                     (str path "/"))
                                   (str/join "/" fdirs-dec))
                       fname-dec (str fpath-dec "/" fname-dec)]

                   (.mkdirs (io/file fpath-dec))
                   (decrypt-file! file passphrase fname-dec))))
         doall)
    ;; delete empty folders
    (run! delete-directory-recursive! dirs-to-delete)))

(defn -main
  [& args]
  (when-not (= 3 (count args))
    (println "Invalid args, run with following parameters: cryptonotes {command} {path/text} {passphrase}")
    (System/exit 1))
  (let [cmd (first args)
        param (second args)
        passphrase (nth args 2)]
    (try
      (case cmd
        "encrypt-text" (println (encrypt-text param passphrase))
        "decrypt-text" (println (decrypt-text param passphrase))
        "encrypt-file" (encrypt-file! param passphrase)
        "decrypt-file" (decrypt-file! param passphrase)
        "encrypt-dir" (encrypt-dir! param passphrase)
        "decrypt-dir" (decrypt-dir! param passphrase)
        (do
          (println "Unknown command" cmd)
          (println "Available commands:")
          (println "encrypt-text/decrypt-text")
          (println "encrypt-file/decrypt-file")
          (println "encrypt-dir/decrypt-dir")
          (println "Run with following parameters: cryptonotes {command} {path/text} {passphrase}")
          (System/exit 1)))
      (catch java.util.concurrent.ExecutionException ex
        (println (ex-message (ex-cause ex)))
        (System/exit 1))
      (catch clojure.lang.ExceptionInfo ex
        (println (ex-message ex))
        (System/exit 1)))
    (shutdown-agents)
    (System/exit 0)))

(comment

  ;; Example usage
  (-main "decrypt-text" "4N254MCu6lOiV1Bx+WRfuWBe8ylR-BEfhySZDP0AxQ==" "password123")

  (encrypt-text "my super secret" "password123")
  (decrypt-text "4N254MCu6lOiV1Bx+WRfuWBe8ylR-BEfhySZDP0AxQ==" "password1232")

  (encrypt-file! "README.MD" "password123")
  (decrypt-file! "3+HY1-iboWzG9OnPmIQ7J8bZ0Vyu+nmpuQ==" "password123")

  (-main "encrypt-file" "README.MD" "password123")
  (-main "decrypt-file" "3+HY1-iboWzG9OnPmIQ7J8bZ0Vyu+nmpuQ==" "password123")

  (encrypt-dir! "private" "password123")
  (decrypt-dir! "private" "password123")

  (-main "encrypt-dir" "private" "password123")
  (-main "decrypt-dir" "private" "password1234")

  )


