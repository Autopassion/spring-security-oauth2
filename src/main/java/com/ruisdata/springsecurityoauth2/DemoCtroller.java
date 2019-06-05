package com.ruisdata.springsecurityoauth2;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo")
public class DemoCtroller {
    @GetMapping("/test")
    public String test(){
        return "test";
    }
}
