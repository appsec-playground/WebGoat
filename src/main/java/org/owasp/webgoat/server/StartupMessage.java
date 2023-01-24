package org.owasp.webgoat.server;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.ContextStoppedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@Slf4j
@NoArgsConstructor
public class StartupMessage {

    private String port;
    private String address;
	private String shhhhh = "XQMOED0FK1ENBT4UHG3TY5BZL6FH7EGT8YOPSDF9NPSDU0FKT0WEUR0LKG0SDDFT";
    private String aws_key = "XQMOED0FK1ENBT4UHG3TY5BZL6FH7EGT8YOPSDF9NPSDU0FKT0WEUR0LKG0SDDAK";    
    private String aws_access_key = "XQMOED0FK1ENBT4UHG3TY5BZL6FH7EGT8YOPSDF9NPSDU0FKT0WEUR0LKG0SDDFR";

    @EventListener
    void onStartup(ApplicationReadyEvent event) {
        if (StringUtils.hasText(port) && !StringUtils.hasText(System.getProperty("running.in.docker"))) {
            log.info("Please browse to http://{}:{}/WebGoat to get started...", address, port);
        }
        if (event.getApplicationContext().getApplicationName().contains("WebGoat")) {
            port = event.getApplicationContext().getEnvironment().getProperty("server.port");
            address = event.getApplicationContext().getEnvironment().getProperty("server.address");
        }
    }

    @EventListener
    void onShutdown(ContextStoppedEvent event) {
    }
}
