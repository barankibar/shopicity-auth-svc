package services

import (
	"context"
	"net/http"

	"github.com/barankibar/shopicity-auth-svc/pkg/db"
	"github.com/barankibar/shopicity-auth-svc/pkg/models"
	"github.com/barankibar/shopicity-auth-svc/pkg/pb"
	"github.com/barankibar/shopicity-auth-svc/pkg/utils"
)

type Server struct {
	H   db.Handler
	Jwt utils.JwtWrapper
	pb.UnimplementedAuthServiceServer
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	var user models.User

	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error == nil {
		return &pb.RegisterResponse{
			Status: http.StatusConflict,
			Error:  "EMAIL ALREADY EXISTS",
		}, nil
	}

	user.Email = req.Email
	user.Password = utils.HashPassword(req.Password)

	s.H.DB.Create(&user)

	return &pb.RegisterResponse{
		Status: http.StatusCreated,
	}, nil
}

func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	var user models.User

	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error != nil {
		return &pb.LoginResponse{
				Status: http.StatusNotFound,
				Error:  "USER NOT FOUND",
			},
			nil
	}

	match := utils.CheckPasswordHash(req.Password, user.Password)
	if !match {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error:  "USER NOT FOUND",
		}, nil
	}

	token, _ := s.Jwt.GenerateToken(user)

	return &pb.LoginResponse{
		Status: http.StatusOK,
		Token:  token,
	}, nil
}

func (s *Server) Validate(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	claims, err := s.Jwt.ValidateToken(req.Token)
	if err != nil {
		return &pb.ValidateResponse{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		}, nil
	}

	var user models.User

	if result := s.H.DB.Where(&models.User{Email: claims.Email}).First(&user); result.Error != nil {
		return &pb.ValidateResponse{
			Status: http.StatusNotFound,
			Error:  "USER NOT FOUND",
		}, nil
	}

	return &pb.ValidateResponse{
		Status: http.StatusOK,
		UserID: user.Id,
	}, nil
}
