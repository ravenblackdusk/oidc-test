package org.example.foo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/foo")
@RestController
class FooResource {
    @GetMapping
    String get() {
        return "foo";
    }
}
