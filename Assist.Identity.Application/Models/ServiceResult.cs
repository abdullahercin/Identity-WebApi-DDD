using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text.Json.Serialization;

namespace Assist.Identity.Application.Models
{
    public class ServiceResult<T>
    {

        public ProblemDetails? ProblemDetails { get; set; }
        public T? Data { get; set; }
        public List<string>? ErrorMessage { get; set; }
        [JsonIgnore] public bool IsSuccess => ErrorMessage == null || ErrorMessage.Count == 0;
        [JsonIgnore] public bool IsFail => !IsSuccess;
        [JsonIgnore] public HttpStatusCode Status { get; set; }

        [JsonIgnore] public string? UrlAsCreated { get; set; }

        //static factory method
        public static ServiceResult<T> Success(T data, HttpStatusCode status = HttpStatusCode.OK)
        {
            return new ServiceResult<T>()
            {
                Data = data,
                Status = status
            };
        }

        public static ServiceResult<T> SuccessAsCreated(T data, string urlAsCreated)
        {
            return new ServiceResult<T>()
            {
                Data = data,
                Status = HttpStatusCode.Created,
                UrlAsCreated = urlAsCreated
            };
        }


        public static ServiceResult<T> Fail(List<string> errorMessage,
            HttpStatusCode status = HttpStatusCode.BadRequest)
        {
            return new ServiceResult<T>()
            {
                ErrorMessage = errorMessage,
                Status = status
            };
        }

        public static ServiceResult<T> Fail(ProblemDetails problemDetails,
            HttpStatusCode status = HttpStatusCode.BadRequest)
        {
            return new ServiceResult<T>()
            {
                ProblemDetails = problemDetails,
                Status = status
            };
        }

        public static ServiceResult<T> Fail(string errorMessage, HttpStatusCode status = HttpStatusCode.BadRequest)
        {
            return new ServiceResult<T>()
            {
                ErrorMessage = [errorMessage],
                Status = status
            };
        }
    }

    public class ServiceResult
    {
        public ProblemDetails? ProblemDetails { get; set; }
        public List<string>? ErrorMessage { get; set; }

        [JsonIgnore] public bool IsSuccess => ErrorMessage == null || ErrorMessage.Count == 0;
        [JsonIgnore] public bool IsFail => !IsSuccess;
        [JsonIgnore] public HttpStatusCode Status { get; set; }

        //static factory method
        public static ServiceResult Success(HttpStatusCode status = HttpStatusCode.OK)
        {
            return new ServiceResult()
            {
                Status = status
            };
        }

        public static ServiceResult Fail(List<string> errorMessage,
            HttpStatusCode status = HttpStatusCode.BadRequest)
        {
            return new ServiceResult()
            {
                ErrorMessage = errorMessage,
                Status = status
            };
        }

        public static ServiceResult Fail(ProblemDetails problemDetails,
            HttpStatusCode status = HttpStatusCode.BadRequest)
        {
            return new ServiceResult()
            {
                ProblemDetails = problemDetails,
                Status = status
            };
        }


        public static ServiceResult Fail(string errorMessage, HttpStatusCode status = HttpStatusCode.BadRequest)
        {
            return new ServiceResult()
            {
                ErrorMessage = [errorMessage],
                Status = status
            };
        }
    }
}
