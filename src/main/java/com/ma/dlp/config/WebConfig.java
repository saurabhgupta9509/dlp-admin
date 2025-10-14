package com.ma.dlp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Serve static HTML files from root directory
        registry.addResourceHandler("/*.html")
                .addResourceLocations("classpath:/static/", "classpath:/public/", "file:./");

        // Serve CSS, JS, images
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/static/", "classpath:/public/", "file:./");
    }
}