namespace Assist.Identity.Domain.ValueObjects
{
    public class AuthorizationLevelEnum
    {
        public enum AuthorizationLevel
        {
            /// <summary>Hiç yetki yok</summary>
            NoAccess = 0,

            /// <summary>Sınırlı yetki</summary>
            LimitedUser = 1,

            /// <summary>Standart kullanıcı</summary>
            StandardUser = 2,

            /// <summary>Güçlü kullanıcı (çok role/permission)</summary>
            PowerUser = 3,

            /// <summary>Administrator</summary>
            Administrator = 4
        }
    }
}
