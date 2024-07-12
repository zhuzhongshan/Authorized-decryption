package net.nharyes.secrete.FileClass;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class GenerateFile {
    public static void main(String[] args) {
        int fileSizeInKilobytes = 1 ; // 50KB
        String fileName = "large1.txt";

        try {
            generateFile(fileName, fileSizeInKilobytes);
            System.out.println("文件生成成功： " + fileName);
        } catch (IOException e) {
            System.err.println("文件生成失败： " + e.getMessage());
        }
    }

    private static void generateFile(String fileName, int fileSizeInKilobytes) throws IOException {
        byte[] buffer = new byte[1024];
        Random random = new Random();
        File file = new File(fileName);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            int remainingBytes = fileSizeInKilobytes * 1024;
            while (remainingBytes > 0) {
                for (int i = 0; i < buffer.length && remainingBytes > 0; i++) {
                    buffer[i] = (byte) ('A' + random.nextInt(26)); // 生成随机字母
                }
                int bytesToWrite = Math.min(buffer.length, remainingBytes);
//                buffer[]='\n';
                fos.write(buffer, 0, bytesToWrite);
                remainingBytes -= bytesToWrite;
            }
        }
    }
}

