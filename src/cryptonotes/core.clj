(ns cryptonotes.core
  (:import (java.io File)
           (java.nio.charset Charset StandardCharsets)
           (java.security MessageDigest)
           (java.security.spec AlgorithmParameterSpec)
           (java.time Instant)
           [javax.crypto AEADBadTagException Cipher CipherOutputStream SecretKeyFactory]
           [javax.crypto.spec SecretKeySpec]
           [javax.crypto.spec IvParameterSpec PBEKeySpec]
           [java.util Base64])
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:gen-class))

(set! *warn-on-reflection* true)

(def ^AlgorithmParameterSpec nonce
  (IvParameterSpec. (byte-array 12)))                       ; 96-bit IV

;; benchmarks https://medium.com/@gerritjvv/aes-java-encryption-performance-benchmarks-3c2cb19a40e9
;; ChaCha20-Poly1305
;; https://blog.cloudflare.com/do-the-chacha-better-mobile-performance-with-cryptography/

(defn ^SecretKeySpec generate-secret-key
  ([passphrase] (generate-secret-key passphrase "nosalt"))
  ([^String passphrase ^String salt]
   (let [key-factory (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA256")
         iteration-count 10000
         key-spec (PBEKeySpec. (.toCharArray passphrase)
                               (.getBytes salt StandardCharsets/UTF_8)
                               iteration-count 256)]        ; Key length in bits
     (let [secret-key (.generateSecret key-factory key-spec)]
       (SecretKeySpec. (.getEncoded secret-key) "ChaCha20")))))

(defn escape-base64 [base64]
  (str/replace base64 #"/" "-"))

(defn ^String unescape-base64 [base64]
  (str/replace base64 #"-" "/"))

(defn byte-arrays-equal? [a b]
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
          (throw (Exception. "Failed to decrypt file")))))))

(defn calculate-checksum [file-path]
  (let [digest (MessageDigest/getInstance "MD5")
        buffer (make-array Byte/TYPE 8192)]
    (with-open [input-stream (io/input-stream file-path)]
      (loop []
        (let [n (.read input-stream buffer)]
          (when (not= n -1)
            (.update digest buffer 0 n)
            (recur)))))
    (.digest digest)))

(defn ensure-integrity! [orig-file encrypted-file ^SecretKeySpec key]
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

(defn encrypt-file
  ([input-file passphrase]
   (let [file (io/file input-file)
         parent (.getParent file)
         fname-enc (encrypt-text (.getName file) passphrase)
         output-file (if parent
                       (str parent "/" fname-enc)
                       fname-enc)]
     (encrypt-file input-file passphrase output-file)))
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

(defn decrypt-file
  ([input-file passphrase]
   (let [file (io/file input-file)
         parent (.getParent file)
         fname-dec (decrypt-text (.getName file) passphrase)
         output-file (if parent
                       (str parent "/" fname-dec)
                       fname-dec)]
     (decrypt-file input-file passphrase output-file)))
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
         (throw (Exception. "Failed to decrypt file"))))
     (.delete (io/file input-file)))))

(defn -main
  [& args]
  (let [cmd (first args)
        param (second args)
        password (nth args 2)]
    (case cmd
      "encrypt-text" (println (encrypt-text param password))
      "decrypt-text" (println (decrypt-text param password))
      "encrypt-file" (encrypt-file param password)
      "decrypt-file" (decrypt-file param password)
      (println "Unknown command" cmd))))

(comment
  ;; Example usage

  ;; key must be 256 bits which is 32 char string = 32 * 8
  (encrypt-file "README.copy.MD" "asdfeghj")

  (calculate-checksum "README.copy.MD")
  (calculate-checksum "tCzm0P8FM22-CQu2S5WUxl2SCjqMz91Z-aoRSlJG")

  (decrypt-file "tCzm0P8FM22-CQu2S5WUxl2SCjqMz91Z-aoRSlJG" "asdfeghja")

  (encrypt-text "my-folder" "test")

  (decrypt-text "MxdWwtVRtPqNbi0SvKESrIorsT9Qfsyrjg=="
                "test")

  )


