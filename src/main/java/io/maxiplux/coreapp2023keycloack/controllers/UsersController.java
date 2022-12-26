package io.maxiplux.coreapp2023keycloack.controllers;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/users")
public class UsersController {

    @GetMapping("/status/check")
    public String status(Principal principal) {

        return "working";
    }
}
