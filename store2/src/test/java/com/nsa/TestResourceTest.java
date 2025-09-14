package com.nsa;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;

@QuarkusTest
public class TestResourceTest {

    @Test
    void testGet_AccountNotFound() {
        given()
            .when().get("/api/test/someName")
            .then()
            .statusCode(404);
    }

    @Test
    void testPost_AccountNotFound() {
        given()
            .when().post("api/test/someName/superAdmin")
            .then()
            .statusCode(404);
    }
}