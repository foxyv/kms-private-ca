package test.tools;

import dev.wobbegong.kmsca.utils.X509Utils;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

public class TestCertDownloader {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java TestCertDownloader <host> <port>");
            System.exit(1);
            return;
        }

        int port;
        String host = args[0];
        if(args.length > 1) {
            port = Integer.parseInt(args[1]);
        } else {
            port = 443;
        }

        System.out.println("Downloading certificate from " + host + ":" + port);
        var certs = X509Utils.downloadCertificate(host, port);

        try (FileOutputStream fos = new FileOutputStream(host + "_" + port + ".pem")) {
            for (var cert : certs){
                fos.write(X509Utils.toPEM(cert).getBytes());
                fos.write("\n".getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
