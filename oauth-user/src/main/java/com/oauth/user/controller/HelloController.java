package com.oauth.user.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author Cheng Yufei
 * @create 2020-11-02 15:23
 **/
@RestController
@RequestMapping("/hello")
public class HelloController {


	/**
	 *
	 * @return
	 */
	@GetMapping("/")
	public String read() {
		return "hello success";
	}
	
}
