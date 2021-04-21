using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Security;
using System.Text;
using System.Threading;

// ReSharper disable UnusedMember.Global
// ReSharper disable InconsistentNaming

namespace Leaf.xNet
{
    /// <inheritdoc />
    /// <summary>
    /// Представляет базовую реализацию класса для работы с прокси-сервером.
    /// </summary>
    public abstract class ProxyClient : IEquatable<ProxyClient>
    {
        #region Поля (защищённые)

        /// <summary>Тип прокси-сервера.</summary>
        protected ProxyType _type;

        /// <summary>Имя пользователя для авторизации на прокси-сервере.</summary>
        protected string _username;

        /// <summary>Пароль для авторизации на прокси-сервере.</summary>
        protected string _password;

        /// <summary>Время ожидания в миллисекундах при подключении к прокси-серверу.</summary>
        private int _connectTimeout = 9 * 1000; // 9 Seconds

        /// <summary>Время ожидания в миллисекундах при записи в поток или при чтении из него.</summary>
        private int _readWriteTimeout = 30 * 1000; // 30 Seconds

        #endregion


        #region Свойства (открытые)

        /// <summary>
        /// Возвращает тип прокси-сервера.
        /// </summary>
        public ProxyType Type => _type;
        
        /// <summary>
        /// Хост прокси-сервера.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        // ReSharper disable once MemberCanBePrivate.Global
        public string Host { get; }
        
        /// <summary>
        /// Порт прокси-сервера.
        /// </summary>
        /// <value>Значение по умолчанию — 1.</value>
        // ReSharper disable once MemberCanBePrivate.Global
        public int Port { get; } = 1;

        /// <summary>
        /// Возвращает или задаёт имя пользователя для авторизации на прокси-сервере.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        /// <exception cref="System.ArgumentOutOfRangeException">Значение параметра имеет длину более 255 символов.</exception>
        public string Username
        {
            get => _username;
            // ReSharper disable once MemberCanBePrivate.Global
            set {
                #region Проверка параметра

                if (value != null && value.Length > 255)
                {
                    throw new ArgumentOutOfRangeException(nameof(Username), string.Format(
                        Resources.ArgumentOutOfRangeException_StringLengthCanNotBeMore, 255));
                }

                #endregion

                _username = value;
            }
        }

        /// <summary>
        /// Возвращает или задаёт пароль для авторизации на прокси-сервере.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        /// <exception cref="System.ArgumentOutOfRangeException">Значение параметра имеет длину более 255 символов.</exception>
        public string Password
        {
            get => _password;
            // ReSharper disable once MemberCanBePrivate.Global
            set {
                #region Проверка параметра

                if (value != null && value.Length > 255)
                {
                    throw new ArgumentOutOfRangeException(nameof(Password), string.Format(
                        Resources.ArgumentOutOfRangeException_StringLengthCanNotBeMore, 255));
                }

                #endregion

                _password = value;
            }
        }

        /// <summary>
        /// Возвращает или задаёт время ожидания в миллисекундах при подключении к прокси-серверу.
        /// </summary>
        /// <value>Значение по умолчанию - 9 000 мс, что равняется 9 секундам.</value>
        /// <exception cref="System.ArgumentOutOfRangeException">Значение параметра меньше 0.</exception>
        // ReSharper disable once UnusedMember.Global
        public int ConnectTimeout
        {
            get => _connectTimeout;
            set {
                #region Проверка параметра

                if (value < 0)
                    throw ExceptionHelper.CanNotBeLess("ConnectTimeout", 0);

                #endregion

                _connectTimeout = value;
            }
        }

        /// <summary>
        /// Возвращает или задает время ожидания в миллисекундах при записи в поток или при чтении из него.
        /// </summary>
        /// <value>Значение по умолчанию - 30 000 мс, что равняется 30 секундам.</value>
        /// <exception cref="System.ArgumentOutOfRangeException">Значение параметра меньше 0.</exception>
        public int ReadWriteTimeout
        {
            get => _readWriteTimeout;
            set {
                #region Проверка параметра

                if (value < 0)
                    throw ExceptionHelper.CanNotBeLess(nameof(ReadWriteTimeout), 0);

                #endregion

                _readWriteTimeout = value;
            }
        }

        /// <summary>
        /// Возвращает или задает значение, следует ли задавать полный адрес ресурса в заголовке запроса специально для прокси.
        /// Если задано <see langword="true"/> (по умолчанию) - если прокси задан верно, использовать абсолютный адрес в заголовке запроса.
        /// Если задано <see langword="false"/> - всегда будет использован относительный адрес в заголовке запроса.
        /// </summary>
        // ReSharper disable once MemberCanBePrivate.Global
        public bool AbsoluteUriInStartingLine { get; set; }

        #endregion


        #region Конструкторы (защищённые)

        /// <summary>
        /// Инициализирует новый экземпляр класса <see cref="ProxyClient"/>.
        /// </summary>
        /// <param name="proxyType">Тип прокси-сервера.</param>
        // ReSharper disable once UnusedMember.Global
        protected internal ProxyClient(ProxyType proxyType)
        {
            _type = proxyType;
        }

        /// <summary>
        /// Инициализирует новый экземпляр класса <see cref="ProxyClient"/>.
        /// </summary>
        /// <param name="proxyType">Тип прокси-сервера.</param>
        /// <param name="address">Хост прокси-сервера.</param>
        /// <param name="port">Порт прокси-сервера.</param>
        // ReSharper disable once UnusedMember.Global
        protected internal ProxyClient(ProxyType proxyType, string address, int port)
        {
            _type = proxyType;
            Host = address;
            Port = port;
        }

        /// <summary>
        /// Инициализирует новый экземпляр класса <see cref="ProxyClient"/>.
        /// </summary>
        /// <param name="proxyType">Тип прокси-сервера.</param>
        /// <param name="address">Хост прокси-сервера.</param>
        /// <param name="port">Порт прокси-сервера.</param>
        /// <param name="username">Имя пользователя для авторизации на прокси-сервере.</param>
        /// <param name="password">Пароль для авторизации на прокси-сервере.</param>
        protected internal ProxyClient(ProxyType proxyType, string address, int port, string username, string password)
        {
            _type = proxyType;
            Host = address;
            Port = port;
            _username = username;
            _password = password;
        }

        #endregion


        #region Статические свойства (защищенные)

        /// <summary>
        /// HTTPS прокси сервер для отладки (Charles / Fiddler).
        /// По умолчанию используется адрес 127.0.0.1:8888.
        /// </summary>
        public static HttpProxyClient DebugHttpProxy {
            get {
                if (_debugHttpProxy != null)
                    return _debugHttpProxy;

                _debugHttpProxy = HttpProxyClient.Parse("127.0.0.1:8888");
                return _debugHttpProxy;
            }
        }
        private static HttpProxyClient _debugHttpProxy;

        /// <summary>
        /// SOCKS5 прокси сервер для отладки (Charles / Fiddler).
        /// По умолчанию используется адрес 127.0.0.1:8889.
        /// </summary>
        public static Socks5ProxyClient DebugSocksProxy => _debugSocksProxy ?? (_debugSocksProxy = Socks5ProxyClient.Parse("127.0.0.1:8889"));
        private static Socks5ProxyClient _debugSocksProxy;

        #endregion


        #region Статические методы

        /// <summary>
        /// Служит для преобразования строковых прокси к объекту ProxyClient.
        /// </summary>
        // ReSharper disable once MemberCanBePrivate.Global
        public static readonly Dictionary<string, ProxyType> ProxyProtocol = new Dictionary<string, ProxyType> {
            {"http", ProxyType.HTTP},
            {"https", ProxyType.HTTP},
            {"socks4", ProxyType.Socks4},
            {"socks4a", ProxyType.Socks4A},
            {"socks5", ProxyType.Socks5},
            {"socks", ProxyType.Socks5}
        };

        /// <summary>
        /// Преобразует строку в экземпляр класса прокси-клиента, унаследованный от <see cref="ProxyClient"/>.
        /// </summary>
        /// <param name="proxyType">Тип прокси-сервера.</param>
        /// <param name="proxyAddress">Строка вида - хост:порт:имя_пользователя:пароль. Три последних параметра являются необязательными.</param>
        /// <returns>Экземпляр класса прокси-клиента, унаследованный от <see cref="ProxyClient"/>.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="proxyAddress"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="proxyAddress"/> является пустой строкой.</exception>
        /// <exception cref="System.FormatException">Формат порта является неправильным.</exception>
        /// <exception cref="System.InvalidOperationException">Получен неподдерживаемый тип прокси-сервера.</exception>
        // ReSharper disable once MemberCanBeProtected.Global
        public static ProxyClient Parse(ProxyType proxyType, string proxyAddress)
        {
            #region Проверка параметров

            if (proxyAddress == null)
                throw new ArgumentNullException(nameof(proxyAddress));

            if (proxyAddress.Length == 0)
                throw ExceptionHelper.EmptyString(nameof(proxyAddress));

            #endregion

            var values = proxyAddress.Split(':');

            int port = 0;
            string host = values[0];

            if (values.Length >= 2)
            {
                #region Получение порта

                try
                {

                    port = int.Parse(values[1].Contains("@") ? values[1].Split('@')[0] : values[1]);
                }
                catch (Exception ex)
                {
                    if (ex is FormatException || ex is OverflowException)
                    {
                        throw new FormatException(
                            Resources.InvalidOperationException_ProxyClient_WrongPort, ex);
                    }

                    throw;
                }

                if (!ExceptionHelper.ValidateTcpPort(port))
                {
                    throw new FormatException(
                        Resources.InvalidOperationException_ProxyClient_WrongPort);
                }

                #endregion
            }

            string username = null;
            string password = null;

            if (proxyAddress.Contains("@"))
            {
                username = proxyAddress.Split('@')[1].Split(':')[0];
                password = proxyAddress.Split('@')[1].Split(':')[1];
            }
            else
            {
                if (values.Length >= 3)
                    username = values[2];

                if (values.Length >= 4)
                    password = values[3];
            }

            return ProxyHelper.CreateProxyClient(proxyType, host, port, username, password);
        }

        /// <inheritdoc cref="Parse(Leaf.xNet.ProxyType,string)"/>
        /// <param name="protoProxyAddress">Строка вида - протокол://хост:порт:имя_пользователя:пароль. Три последних параметра являются необязательными.</param>
        /// <returns>Экземпляр класса прокси-клиента, унаследованный от <see cref="ProxyClient"/>.</returns>
        // ReSharper disable once UnusedMember.Global
        public static ProxyClient Parse(string protoProxyAddress)
        {
            var proxy = protoProxyAddress.Split(new[] {"://"}, StringSplitOptions.RemoveEmptyEntries);
            if (proxy.Length < 2)
                return null;

            string proto = proxy[0];
            if (!ProxyProtocol.ContainsKey(proto))
                return null;

            var proxyType = ProxyProtocol[proto];
            return Parse(proxyType, proxy[1]);
        }

        /// <summary>
        /// Преобразует строку в экземпляр класса прокси-клиента, унаследованный от <see cref="ProxyClient"/>. Возвращает значение, указывающее, успешно ли выполнено преобразование.
        /// </summary>
        /// <param name="proxyType">Тип прокси-сервера.</param>
        /// <param name="proxyAddress">Строка вида - хост:порт:имя_пользователя:пароль. Три последних параметра являются необязательными.</param>
        /// <param name="result">Если преобразование выполнено успешно, то содержит экземпляр класса прокси-клиента, унаследованный от <see cref="ProxyClient"/>, иначе <see langword="null"/>.</param>
        /// <returns>Значение <see langword="true"/>, если параметр <paramref name="proxyAddress"/> преобразован успешно, иначе <see langword="false"/>.</returns>
        // ReSharper disable once MemberCanBeProtected.Global
        public static bool TryParse(ProxyType proxyType, string proxyAddress, out ProxyClient result)
        {
            result = null;

            #region Проверка параметров

            if (string.IsNullOrEmpty(proxyAddress))
                return false;

            #endregion

            var values = proxyAddress.Split(':');

            int port = 0;
            string host = values[0];

            if (values.Length >= 2 &&
                (!int.TryParse(values[1], out port) || !ExceptionHelper.ValidateTcpPort(port)))
            {
                return false;
            }

            string username = null;
            string password = null;

            if (values.Length >= 3)
                username = values[2];

            if (values.Length >= 4)
                password = values[3];

            try
            {
                result = ProxyHelper.CreateProxyClient(proxyType, host, port, username, password);
            }
            catch (InvalidOperationException)
            {
                return false;
            }

            return true;
        }

        /// <inheritdoc cref="TryParse(Leaf.xNet.ProxyType,string,out Leaf.xNet.ProxyClient)"/>
        /// <param name="protoProxyAddress">Строка вида - протокол://хост:порт:имя_пользователя:пароль. Три последних параметра являются необязательными.</param>
        /// <param name="result">Результат - абстрактный клиент прокси</param>
        /// <returns>Значение <see langword="true"/>, если параметр <paramref name="protoProxyAddress"/> преобразован успешно, иначе <see langword="false"/>.</returns>
        // ReSharper disable once UnusedMember.Global
        public static bool TryParse(string protoProxyAddress, out ProxyClient result)
        {
            var proxy = protoProxyAddress.Split(new[] {"://"}, StringSplitOptions.RemoveEmptyEntries);
            if (proxy.Length < 2 || !ProxyProtocol.ContainsKey(proxy[0]))
            {
                result = null;
                return false;
            }

            var proxyType = ProxyProtocol[proxy[0]];
            return TryParse(proxyType, proxy[1], out result);
        }

        #endregion


        /// <summary>
        /// Создаёт соединение с сервером через прокси-сервер.
        /// </summary>
        /// <param name="destinationHost">Хост пункта назначения, с которым нужно связаться через прокси-сервер.</param>
        /// <param name="destinationPort">Порт пункта назначения, с которым нужно связаться через прокси-сервер.</param>
        /// <param name="tcpClient">Соединение, через которое нужно работать, или значение <see langword="null"/>.</param>
        /// <returns>Соединение с прокси-сервером.</returns>
        /// <exception cref="System.InvalidOperationException">
        /// Значение свойства <see cref="Host"/> равно <see langword="null"/> или имеет нулевую длину.
        /// -или-
        /// Значение свойства <see cref="Port"/> меньше 1 или больше 65535.
        /// -или-
        /// Значение свойства <see cref="Username"/> имеет длину более 255 символов.
        /// -или-
        /// Значение свойства <see cref="Password"/> имеет длину более 255 символов.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="destinationHost"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="destinationHost"/> является пустой строкой.</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Значение параметра <paramref name="destinationPort"/> меньше 1 или больше 65535.</exception>
        /// <exception cref="Leaf.xNet.ProxyException">Ошибка при работе с прокси-сервером.</exception>
        public abstract TcpClient CreateConnection(string destinationHost, int destinationPort,
            TcpClient tcpClient = null);


        #region Методы (открытые)

        /// <summary>
        /// Формирует строку вида - хост:порт, представляющую адрес прокси-сервера.
        /// </summary>
        /// <returns>Строка вида - хост:порт, представляющая адрес прокси-сервера.</returns>
        public override string ToString() => $"{Host}:{Port}";

        /// <summary>
        /// Формирует строку вида - хост:порт:имя_пользователя:пароль. Последние два параметра добавляются, если они заданы.
        /// </summary>
        /// <returns>Строка вида - хост:порт:имя_пользователя:пароль.</returns>
        // ReSharper disable once UnusedMember.Global
        public string ToExtendedString()
        {
            var strBuilder = new StringBuilder();

            strBuilder.AppendFormat("{0}:{1}", Host, Port);

            if (string.IsNullOrEmpty(_username))
                return strBuilder.ToString();

            strBuilder.AppendFormat(":{0}", _username);

            if (!string.IsNullOrEmpty(_password))
                strBuilder.AppendFormat(":{0}", _password);

            return strBuilder.ToString();
        }

        /// <summary>
        /// Возвращает хэш-код для этого прокси-клиента.
        /// </summary>
        /// <returns>Хэш-код в виде 32-битового целого числа со знаком.</returns>
        public override int GetHashCode()
        {
            if (string.IsNullOrEmpty(Host))
                return 0;

            return Host.GetHashCode() ^ Port;
        }

        /// <inheritdoc/>
        /// <summary>
        /// Определяет, равны ли два прокси-клиента.
        /// </summary>
        /// <param name="proxy">Прокси-клиент для сравнения с данным экземпляром.</param>
        /// <returns>Значение <see langword="true"/>, если два прокси-клиента равны, иначе значение <see langword="false"/>.</returns>
        public bool Equals(ProxyClient proxy)
        {
            if (proxy == null || Host == null)
                return false;

            return Host.Equals(proxy.Host, StringComparison.OrdinalIgnoreCase) && Port == proxy.Port;
        }

        /// <summary>
        /// Определяет, равны ли два прокси-клиента.
        /// </summary>
        /// <param name="obj">Прокси-клиент для сравнения с данным экземпляром.</param>
        /// <returns>Значение <see langword="true"/>, если два прокси-клиента равны, иначе значение <see langword="false"/>.</returns>
        public override bool Equals(object obj) => obj is ProxyClient proxy && Equals(proxy);

        #endregion


        #region Методы (защищённые)

        /// <summary>
        /// Создаёт соединение с прокси-сервером.
        /// </summary>
        /// <returns>Соединение с прокси-сервером.</returns>
        /// <exception cref="Leaf.xNet.ProxyException">Ошибка при работе с прокси-сервером.</exception>
        protected TcpClient CreateConnectionToProxy()
        {
            #region Создание подключения

            var tcpClient = new TcpClient();
            Exception connectException = null;
            var connectDoneEvent = new ManualResetEventSlim();

            try
            {
                tcpClient.BeginConnect(Host, Port, ar => {
                    if (tcpClient.Client == null)
                        return;

                    try
                    {
                        tcpClient.EndConnect(ar);
                    }
                    catch (Exception ex)
                    {
                        connectException = ex;
                    }

                    connectDoneEvent.Set();
                }, tcpClient);
            }

            #region Catch's

            catch (Exception ex)
            {
                tcpClient.Close();

                if (ex is SocketException || ex is SecurityException)
                    throw NewProxyException(Resources.ProxyException_FailedConnect, ex);

                throw;
            }

            #endregion

            if (!connectDoneEvent.Wait(_connectTimeout))
            {
                tcpClient.Close();
                throw NewProxyException(Resources.ProxyException_ConnectTimeout);
            }

            if (connectException != null)
            {
                tcpClient.Close();

                if (connectException is SocketException)
                    throw NewProxyException(Resources.ProxyException_FailedConnect, connectException);

                throw connectException;
            }

            if (!tcpClient.Connected)
            {
                tcpClient.Close();
                throw NewProxyException(Resources.ProxyException_FailedConnect);
            }

            #endregion

            tcpClient.SendTimeout = _readWriteTimeout;
            tcpClient.ReceiveTimeout = _readWriteTimeout;

            return tcpClient;
        }

        /// <summary>
        /// Проверяет различные параметры прокси-клиента на ошибочные значения.
        /// </summary>
        /// <exception cref="System.InvalidOperationException">Значение свойства <see cref="Host"/> равно <see langword="null"/> или имеет нулевую длину.</exception>
        /// <exception cref="System.InvalidOperationException">Значение свойства <see cref="Port"/> меньше 1 или больше 65535.</exception>
        /// <exception cref="System.InvalidOperationException">Значение свойства <see cref="Username"/> имеет длину более 255 символов.</exception>
        /// <exception cref="System.InvalidOperationException">Значение свойства <see cref="Password"/> имеет длину более 255 символов.</exception>
        protected void CheckState()
        {
            if (string.IsNullOrEmpty(Host))
            {
                throw new InvalidOperationException(
                    Resources.InvalidOperationException_ProxyClient_WrongHost);
            }

            if (!ExceptionHelper.ValidateTcpPort(Port))
            {
                throw new InvalidOperationException(
                    Resources.InvalidOperationException_ProxyClient_WrongPort);
            }

            if (_username != null && _username.Length > 255)
            {
                throw new InvalidOperationException(
                    Resources.InvalidOperationException_ProxyClient_WrongUsername);
            }

            if (_password != null && _password.Length > 255)
            {
                throw new InvalidOperationException(
                    Resources.InvalidOperationException_ProxyClient_WrongPassword);
            }
        }

        /// <summary>
        /// Создаёт объект исключения прокси.
        /// </summary>
        /// <param name="message">Сообщение об ошибке с объяснением причины исключения.</param>
        /// <param name="innerException">Исключение, вызвавшее текущие исключение, или значение <see langword="null"/>.</param>
        /// <returns>Объект исключения прокси.</returns>
        protected ProxyException NewProxyException(
            string message, Exception innerException = null)
        {
            return new ProxyException(string.Format(
                message, ToString()), this, innerException);
        }

        #endregion
    }
}
