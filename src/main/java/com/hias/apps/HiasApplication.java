package com.hias.apps;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import de.codecentric.boot.admin.server.config.EnableAdminServer;
//import org.springframework.context.annotation.ComponentScan;
//import org.springframework.context.annotation.Configuration;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@EnableAdminServer
@EnableAutoConfiguration
@SpringBootApplication
@EnableSwagger2
public class HiasApplication {

	public static void main(String[] args) {
		SpringApplication.run(HiasApplication.class, args);
	}
}
