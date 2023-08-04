package main

import (
	"fmt"
	"log"
	"net"

	"github.com/barankibar/shopicity-auth-svc/pkg/config"
	"github.com/barankibar/shopicity-auth-svc/pkg/db"
	"github.com/barankibar/shopicity-auth-svc/pkg/pb"
	"github.com/barankibar/shopicity-auth-svc/pkg/services"
	"github.com/barankibar/shopicity-auth-svc/pkg/utils"
	"google.golang.org/grpc"
)

func main() {
	env, err := config.LoadConfig()
	if err != nil {
		log.Fatalln("FAILED AT CONFIG: ", err)
	}

	h := db.Init(env.DBUrl)

	jwt := utils.JwtWrapper{
		SecretKey:       env.JWTSecretKey,
		Issuer:          "go-grpc-auth-svc",
		ExpirationHours: 24 * 365,
	}

	lis, err := net.Listen("tcp", env.Port)
	if err != nil {
		log.Fatalln("Failed to listing:", err)
	}
	fmt.Println("Auth Svc on", env.Port)

	grpcServer := grpc.NewServer()

	s := services.Server{
		H:   h,
		Jwt: jwt,
	}

	pb.RegisterAuthServiceServer(grpcServer, &s)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalln("Failed to serve:", err)
	}

}
