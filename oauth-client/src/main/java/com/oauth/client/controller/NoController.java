package com.oauth.client.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author Cheng Yufei
 * @create 2020-11-06 17:21
 **/
@RestController
public class NoController {

    @GetMapping(value = "/no/free", produces = "application/json")
    public Object remoteApiFree() {
        return "remoteApi-Free";
    }

}
