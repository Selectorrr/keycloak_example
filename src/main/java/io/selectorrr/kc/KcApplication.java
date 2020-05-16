package io.selectorrr.kc;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@Slf4j
public class KcApplication {

    public static void main(String[] args) {
        SpringApplication.run(KcApplication.class, args);
        log.info("Заходи сюда: http://localhost:8080");
    }

}
