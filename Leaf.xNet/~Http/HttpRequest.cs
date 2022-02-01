using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using Leaf.xNet.Services.Captcha;

// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable UnusedMember.Global
// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global
// ReSharper disable MemberCanBePrivate.Global

namespace Leaf.xNet
{
    /// <inheritdoc />
    /// <summary>
    /// Class to send HTTP-server requests.
    /// </summary>
    public sealed class HttpRequest : IDisposable
    {
        // Используется для определения того, сколько байт было отправлено/считано.
        private sealed class HttpWrapperStream : Stream
        {
            #region Поля (закрытые)

            private readonly Stream _baseStream;
            private readonly int _sendBufferSize;

            #endregion


            #region Свойства (открытые)

            public Action<int> BytesReadCallback { private get; set; }

            public Action<int> BytesWriteCallback { private get; set; }

            #region Переопределённые

            public override bool CanRead => _baseStream.CanRead;

            public override bool CanSeek => _baseStream.CanSeek;

            public override bool CanTimeout => _baseStream.CanTimeout;

            public override bool CanWrite => _baseStream.CanWrite;

            public override long Length => _baseStream.Length;

            public override long Position
            {
                get => _baseStream.Position;
                set => _baseStream.Position = value;
            }

            #endregion

            #endregion


            public HttpWrapperStream(Stream baseStream, int sendBufferSize)
            {
                _baseStream = baseStream;
                _sendBufferSize = sendBufferSize;
            }


            #region Методы (открытые)

            public override void Flush() { }

            public override void SetLength(long value) => _baseStream.SetLength(value);

            public override long Seek(long offset, SeekOrigin origin)
            {
                return _baseStream.Seek(offset, origin);
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                int bytesRead = _baseStream.Read(buffer, offset, count);

                BytesReadCallback?.Invoke(bytesRead);

                return bytesRead;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                if (BytesWriteCallback == null)
                    _baseStream.Write(buffer, offset, count);
                else
                {
                    int index = 0;

                    while (count > 0)
                    {
                        int bytesWrite;

                        if (count >= _sendBufferSize)
                        {
                            bytesWrite = _sendBufferSize;
                            _baseStream.Write(buffer, index, bytesWrite);

                            index += _sendBufferSize;
                            count -= _sendBufferSize;
                        }
                        else
                        {
                            bytesWrite = count;
                            _baseStream.Write(buffer, index, bytesWrite);

                            count = 0;
                        }

                        BytesWriteCallback(bytesWrite);
                    }
                }
            }

            #endregion
        }


        /// <summary>
        /// Version HTTP-protocol, used in requests.
        /// </summary>
        public static Version ProtocolVersion { get; set; } = new Version(1, 1);

        #region Статические свойства (открытые)

        /// <summary>
        /// Возвращает или задаёт значение, указывающие, нужно ли отключать прокси-клиент для локальных адресов.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="false"/>.</value>
        public static bool DisableProxyForLocalAddress { get; set; }

        /// <summary>
        /// Возвращает или задаёт глобальный прокси-клиент.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        public static ProxyClient GlobalProxy { get; set; }

        #endregion


        #region Поля (закрытые)

        private ProxyClient _currentProxy;

        private int _redirectionCount;
        private int _maximumAutomaticRedirections = 5;

        private int _connectTimeout = 9 * 1000; // 9 Seconds
        private int _readWriteTimeout = 30 * 1000; // 30 Seconds

        private DateTime _whenConnectionIdle;
        private int _keepAliveTimeout = 30 * 1000;
        private int _maximumKeepAliveRequests = 100;
        private int _keepAliveRequestCount;
        private bool _keepAliveReconnected;

        private int _reconnectLimit = 3;
        private int _reconnectDelay = 100;
        private int _reconnectCount;

        private HttpMethod _method;
        private HttpContent _content; // Тело запроса.

        private readonly Dictionary<string, string> _permanentHeaders =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Временные данные, которые задаются через специальные методы.
        // Удаляются после первого запроса.
        private Dictionary<string, string> _temporaryHeaders;
        private MultipartContent _temporaryMultipartContent;

        // Количество отправленных и принятых байт.
        // Используются для событий UploadProgressChanged и DownloadProgressChanged.
        private long _bytesSent;
        private long _totalBytesSent;
        private long _bytesReceived;
        private long _totalBytesReceived;
        private bool _canReportBytesReceived;

        private EventHandler<UploadProgressChangedEventArgs> _uploadProgressChangedHandler;
        private EventHandler<DownloadProgressChangedEventArgs> _downloadProgressChangedHandler;

        // Переменные для хранения исходных свойств для переключателя ManualMode (ручной режим)
        private bool _tempAllowAutoRedirect;
        private bool _tempIgnoreProtocolErrors;

        #endregion


        #region События (открытые)

        /// <summary>
        /// Возникает каждый раз при продвижении хода выгрузки данных тела сообщения.
        /// </summary>
        // ReSharper disable once EventNeverSubscribedTo.Global
        public event EventHandler<UploadProgressChangedEventArgs> UploadProgressChanged
        {
            add => _uploadProgressChangedHandler += value;
            // ReSharper disable once DelegateSubtraction
            remove => _uploadProgressChangedHandler -= value;
        }

        /// <summary>
        /// Возникает каждый раз при продвижении хода загрузки данных тела сообщения.
        /// </summary>
        // ReSharper disable once EventNeverSubscribedTo.Global
        public event EventHandler<DownloadProgressChangedEventArgs> DownloadProgressChanged
        {
            add => _downloadProgressChangedHandler += value;
            // ReSharper disable once DelegateSubtraction
            remove => _downloadProgressChangedHandler -= value;
        }

        #endregion


        #region Свойства (открытые)

        /// <summary>
        /// Возвращает или задаёт URI интернет-ресурса, который используется, если в запросе указан относительный адрес.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        public Uri BaseAddress { get; set; }

        /// <summary>
        /// Возвращает URI интернет-ресурса, который фактически отвечает на запрос.
        /// </summary>
        public Uri Address { get; private set; }

        /// <summary>
        /// Возвращает последний ответ от HTTP-сервера, полученный данным экземпляром класса.
        /// </summary>
        public HttpResponse Response { get; private set; }

        /// <summary>
        /// Возвращает или задает прокси-клиент.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        public ProxyClient Proxy { get; set; }

        /// <summary>
        /// Реализация SSL подключения. Провайдер можно задать через <see cref="SslProvider{T}"/>.
        /// </summary>
        private ISslProvider RequestSslProvider {
            get {
                if (_requestSslProvider != null)
                    return _requestSslProvider;

                return _requestSslProvider = new SystemSslProvider();
            }
            set => _requestSslProvider = value;
        }

        private ISslProvider _requestSslProvider;

        /// <summary>
        /// Возвращает или задает возможные протоколы SSL.
        /// По умолчанию используется: <value>SslProtocols.Tls | SslProtocols.Tls12 | SslProtocols.Tls11</value>.
        /// </summary>
        public SslProtocols SslProtocols { get; set; } = SslProtocols.Tls | SslProtocols.Tls12 | SslProtocols.Tls11;

        /// <summary>
        /// Возвращает или задает метод делегата, вызываемый при проверки сертификата SSL, используемый для проверки подлинности.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>. Если установлено значение по умолчанию, то используется метод, который принимает все сертификаты SSL.</value>
        public RemoteCertificateValidationCallback SslCertificateValidatorCallback { get; set; }

        /// <summary>
        /// Разрешает устанавливать пустые значения заголовкам.
        /// </summary>
        public bool AllowEmptyHeaderValues { get; set; }

        /// <summary>
        /// Следует ли отправлять временные заголовки (добавленные через <see cref="AddHeader(string,string)"/>) переадресованным запросам.
        /// По умолчанию <see langword="true"/>.
        /// </summary>
        public bool KeepTemporaryHeadersOnRedirect { get; set; } = true;

        /// <summary>
        /// Включить отслеживание заголовков в промежуточных запросах (переадресованные) и сохранять их в <see cref="HttpResponse.MiddleHeaders"/>.
        /// </summary>
        public bool EnableMiddleHeaders { get; set; }

        /// <summary>
        /// Заголовок AcceptEncoding. Стоит обратить внимание что не все сайты принимают версию с пробелом: "gzip, deflate".
        /// </summary>
        public string AcceptEncoding { get; set; } = "gzip,deflate";

        /// <summary>
        /// Dont throw exception when received cookie name is invalid, just ignore.
        /// </summary>
        public bool IgnoreInvalidCookie { get; set; } = false;

        #region Поведение

        /// <summary>
        /// Возвращает или задает значение, указывающие, должен ли запрос следовать ответам переадресации.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="true"/>.</value>
        public bool AllowAutoRedirect { get; set; }

        /// <summary>
        /// Переводит работу запросами в ручной режим. Указав значение false - вернет исходные значения полей AllowAutoRedirect и IgnoreProtocolErrors.
        /// 1. Отключаются проверка возвращаемых HTTP кодов, исключения не будет если код отличен от 200 OK.
        /// 2. Отключается автоматическая переадресация. 
        /// </summary>
        public bool ManualMode
        {
            get => !AllowAutoRedirect && IgnoreProtocolErrors;
            set {
                if (value)
                {
                    _tempAllowAutoRedirect = AllowAutoRedirect;
                    _tempIgnoreProtocolErrors = IgnoreProtocolErrors;

                    AllowAutoRedirect = false;
                    IgnoreProtocolErrors = true;
                }
                else
                {
                    AllowAutoRedirect = _tempAllowAutoRedirect;
                    IgnoreProtocolErrors = _tempIgnoreProtocolErrors;
                }
            }
        }

        /// <summary>
        /// Возвращает или задает максимальное количество последовательных переадресаций.
        /// </summary>
        /// <value>Значение по умолчанию - 5.</value>
        /// <exception cref="System.ArgumentOutOfRangeException">Значение параметра меньше 1.</exception>
        // ReSharper disable once UnusedMember.Global
        public int MaximumAutomaticRedirections
        {
            get => _maximumAutomaticRedirections;
            set {
                #region Проверка параметра

                if (value < 1)
                    throw ExceptionHelper.CanNotBeLess(nameof(MaximumAutomaticRedirections), 1);

                #endregion

                _maximumAutomaticRedirections = value;
            }
        }

        /// <summary>
        /// Возвращает или задаёт вариант генерации заголовков Cookie.
        /// Если указано значение <value>true</value> - будет сгенерирован лишь один Cookie заголовок, а в нем прописаны все Cookies через разделитель.
        /// Если указано значение <value>false</value> - каждая Cookie будет в новом заголовке (новый формат).
        /// </summary>
        public bool CookieSingleHeader { get; set; } = true;

        /// <summary>
        /// Возвращает или задаёт время ожидания в миллисекундах при подключении к HTTP-серверу.
        /// </summary>
        /// <value>Значение по умолчанию - 9 000 мс, что равняется 9 секундам.</value>
        /// <exception cref="System.ArgumentOutOfRangeException">Значение параметра меньше 0.</exception>
        public int ConnectTimeout
        {
            get => _connectTimeout;
            set {
                #region Проверка параметра

                if (value < 0)
                    throw ExceptionHelper.CanNotBeLess(nameof(ConnectTimeout), 0);

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
        /// Возвращает или задает значение, указывающие, нужно ли игнорировать ошибки протокола и не генерировать исключения.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="false"/>.</value>
        /// <remarks>Если установить значение <see langword="true"/>, то в случае получения ошибочного ответа с кодом состояния 4xx или 5xx, не будет сгенерировано исключение. Вы можете узнать код состояния ответа с помощью свойства <see cref="HttpResponse.StatusCode"/>.</remarks>
        public bool IgnoreProtocolErrors { get; set; }

        /// <summary>
        /// Возвращает или задает значение, указывающее, необходимо ли устанавливать постоянное подключение к интернет-ресурсу.
        /// </summary>
        /// <value>Значение по умолчанию - <see langword="true"/>.</value>
        /// <remarks>Если значение равно <see langword="true"/>, то дополнительно отправляется заголовок 'Connection: Keep-Alive', иначе отправляется заголовок 'Connection: Close'. Если для подключения используется HTTP-прокси, то вместо заголовка - 'Connection', устанавливается заголовок - 'Proxy-Connection'. В случае, если сервер оборвёт постоянное соединение, <see cref="HttpResponse"/> попытается подключиться заново, но это работает только, если подключение идёт напрямую с HTTP-сервером, либо с HTTP-прокси.</remarks>
        public bool KeepAlive { get; set; }

        /// <summary>
        /// Возвращает или задает время простаивания постоянного соединения в миллисекундах, которое используется по умолчанию.
        /// </summary>
        /// <value>Значение по умолчанию - 30.000, что равняется 30 секундам.</value>
        /// <exception cref="System.ArgumentOutOfRangeException">Значение параметра меньше 0.</exception>
        /// <remarks>Если время вышло, то будет создано новое подключение. Если сервер вернёт своё значение таймаута <see cref="HttpResponse.KeepAliveTimeout"/>, тогда будет использовано именно оно.</remarks>
        public int KeepAliveTimeout
        {
            get => _keepAliveTimeout;
            set {
                #region Проверка параметра

                if (value < 0)
                    throw ExceptionHelper.CanNotBeLess(nameof(KeepAliveTimeout), 0);

                #endregion

                _keepAliveTimeout = value;
            }
        }

        /// <summary>
        /// Возвращает или задает максимально допустимое количество запросов для одного соединения, которое используется по умолчанию.
        /// </summary>
        /// <value>Значение по умолчанию - 100.</value>
        /// <exception cref="System.ArgumentOutOfRangeException">Значение параметра меньше 1.</exception>
        /// <remarks>Если количество запросов превысило максимальное, то будет создано новое подключение. Если сервер вернёт своё значение максимального кол-ва запросов <see cref="HttpResponse.MaximumKeepAliveRequests"/>, тогда будет использовано именно оно.</remarks>
        public int MaximumKeepAliveRequests
        {
            get => _maximumKeepAliveRequests;
            set {
                #region Проверка параметра

                if (value < 1)
                    throw ExceptionHelper.CanNotBeLess(nameof(MaximumKeepAliveRequests), 1);

                #endregion

                _maximumKeepAliveRequests = value;
            }
        }

        /// <summary>
        /// Возвращает или задает значение, указывающее, нужно ли пробовать переподключаться через n-миллисекунд, если произошла ошибка во время подключения или отправки/загрузки данных.
        /// </summary>
        /// <value>Значение по умолчанию - <see langword="false"/>.</value>
        public bool Reconnect { get; set; }

        /// <summary>
        /// Возвращает или задает максимальное количество попыток переподключения.
        /// </summary>
        /// <value>Значение по умолчанию - 3.</value>
        /// <exception cref="System.ArgumentOutOfRangeException">Значение параметра меньше 1.</exception>
        // ReSharper disable once UnusedMember.Global
        public int ReconnectLimit
        {
            get => _reconnectLimit;
            set {
                #region Проверка параметра

                if (value < 1)
                    throw ExceptionHelper.CanNotBeLess(nameof(ReconnectLimit), 1);

                #endregion

                _reconnectLimit = value;
            }
        }

        /// <summary>
        /// Возвращает или задает задержку в миллисекундах, которая возникает перед тем, как выполнить переподключение.
        /// </summary>
        /// <value>Значение по умолчанию - 100 миллисекунд.</value>
        /// <exception cref="System.ArgumentOutOfRangeException">Значение параметра меньше 0.</exception>
        // ReSharper disable once UnusedMember.Global
        public int ReconnectDelay
        {
            get => _reconnectDelay;
            set {
                #region Проверка параметра

                if (value < 0)
                    throw ExceptionHelper.CanNotBeLess(nameof(ReconnectDelay), 0);

                #endregion

                _reconnectDelay = value;
            }
        }

        #endregion

        #region HTTP-заголовки

        /// <summary>
        /// Язык, используемый текущим запросом.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        /// <remarks>Если язык установлен, то дополнительно отправляется заголовок 'Accept-Language' с названием этого языка.</remarks>
        public CultureInfo Culture { get; set; }

        /// <summary>
        /// Возвращает или задаёт кодировку, применяемую для преобразования исходящих и входящих данных.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        /// <remarks>Если кодировка установлена, то дополнительно отправляется заголовок 'Accept-Charset' с названием этой кодировки, но только если этот заголовок уже не задан напрямую. Кодировка ответа определяется автоматически, но, если её не удастся определить, то будет использовано значение данного свойства. Если значение данного свойства не задано, то будет использовано значение <see cref="System.Text.Encoding.Default"/>.</remarks>
        public Encoding CharacterSet { get; set; }

        /// <summary>
        /// Возвращает или задает значение, указывающее, нужно ли кодировать содержимое ответа. Это используется, прежде всего, для сжатия данных.
        /// </summary>
        /// <value>Значение по умолчанию - <see langword="true"/>.</value>
        /// <remarks>Если значение равно <see langword="true"/>, то дополнительно отправляется заголовок 'Accept-Encoding: gzip, deflate'.</remarks>
        public bool EnableEncodingContent { get; set; }

        /// <summary>
        /// Возвращает или задаёт имя пользователя для базовой авторизации на HTTP-сервере.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        /// <remarks>Если значение установлено, то дополнительно отправляется заголовок 'Authorization'.</remarks>
        public string Username { get; set; }

        /// <summary>
        /// Возвращает или задаёт пароль для базовой авторизации на HTTP-сервере.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        /// <remarks>Если значение установлено, то дополнительно отправляется заголовок 'Authorization'.</remarks>
        public string Password { get; set; }

        /// <summary>
        /// Возвращает или задает значение HTTP-заголовка 'User-Agent'.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        public string UserAgent
        {
            get => this["User-Agent"];
            set => this["User-Agent"] = value;
        }

        /// <summary>
        /// Изменяет User-Agent на случайный (Chrome, Firefox, Opera, Internet Explorer).
        /// Шансы выпадения соответствуют популярности браузеров.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public void UserAgentRandomize()
        {
            UserAgent = Http.RandomUserAgent();
        }

        /// <summary>
        /// Возвращает или задает значение HTTP-заголовка 'Referer'.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        // ReSharper disable once UnusedMember.Global
        public string Referer
        {
            get => this["Referer"];
            set => this["Referer"] = value;
        }

        /// <summary>
        /// Возвращает или задает значение HTTP-заголовка 'Authorization'.
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="null"/>.</value>
        // ReSharper disable once UnusedMember.Global
        public string Authorization
        {
            get => this["Authorization"];
            set => this["Authorization"] = value;
        }

        /// <summary>
        /// Возвращает или задает куки, связанные с запросом.
        /// Создается автоматически, если задано свойство <see cref="UseCookies"/> в значении <see langword="true"/>.
        /// </summary>
        /// <value>Значение по умолчанию: если <see cref="UseCookies"/> установлено в <see langword="true"/>, то вернется коллекция.
        /// Если <see langword="false"/>, то вернется <see langword="null"/>.</value>
        /// <remarks>Куки могут изменяться ответом от HTTP-сервера. Чтобы не допустить этого, нужно установить свойство <see cref="Leaf.xNet.CookieStorage.IsLocked"/> равным <see langword="true"/>.</remarks>
        public CookieStorage Cookies { get; set; }

        /// <summary>
        /// Позволяет задать автоматическое создание <see cref="CookieStorage"/> в свойстве Cookies когда получены куки от сервера.
        /// Если установить значение в <see langword="false"/> - заголовки с куками не будут отправляться и не будут сохраняться из ответа (заголовок Set-Cookie).
        /// </summary>
        /// <value>Значение по умолчанию — <see langword="true"/>.</value>
        public bool UseCookies { get; set; } = true;

        #endregion

        #region Сервисы

        /// <summary>
        /// Сервис для решения каптч. Применяется для Cloudflare.
        /// </summary>
        public ICaptchaSolver CaptchaSolver { get; set; }

        #endregion

        #endregion


        #region Свойства (внутренние)

        internal TcpClient TcpClient { get; private set; }

        internal Stream ClientStream { get; private set; }

        internal NetworkStream ClientNetworkStream { get; private set; }

        #endregion


        #region Индексаторы (открытые)

        /// <summary>
        /// Возвращает или задаёт значение HTTP-заголовка.
        /// </summary>
        /// <param name="headerName">Название HTTP-заголовка.</param>
        /// <value>Значение HTTP-заголовка, если он задан, иначе пустая строка. Если задать значение <see langword="null"/> или пустую строку, то HTTP-заголовок будет удалён из списка.</value>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="headerName"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="headerName"/> является пустой строкой.
        /// -или-
        /// Установка значения HTTP-заголовка, который должен задаваться с помощью специального свойства/метода.
        /// </exception>
        /// <remarks>Список HTTP-заголовков, которые должны задаваться только с помощью специальных свойств/методов:
        /// <list type="table">
        ///     <item>
        ///        <description>Accept-Encoding</description>
        ///     </item>
        ///     <item>
        ///        <description>Content-Length</description>
        ///     </item>
        ///     <item>
        ///         <description>Content-Type</description>
        ///     </item>
        ///     <item>
        ///        <description>Connection</description>
        ///     </item>
        ///     <item>
        ///        <description>Proxy-Connection</description>
        ///     </item>
        ///     <item>
        ///        <description>Host</description>
        ///     </item>
        /// </list>
        /// </remarks>
        public string this[string headerName]
        {
            get {
                #region Проверка параметра

                if (headerName == null)
                    throw new ArgumentNullException(nameof(headerName));

                if (headerName.Length == 0)
                    throw ExceptionHelper.EmptyString(nameof(headerName));

                #endregion

                if (!_permanentHeaders.TryGetValue(headerName, out string value))
                    value = string.Empty;

                return value;
            }
            set {
                #region Проверка параметра

                if (headerName == null)
                    throw new ArgumentNullException(nameof(headerName));

                if (headerName.Length == 0)
                    throw ExceptionHelper.EmptyString(nameof(headerName));

                #endregion

                if (string.IsNullOrEmpty(value))
                    _permanentHeaders.Remove(headerName);
                else
                    _permanentHeaders[headerName] = value;
            }
        }

        /// <summary>
        /// Возвращает или задаёт значение HTTP-заголовка.
        /// </summary>
        /// <param name="header">HTTP-заголовок.</param>
        /// <value>Значение HTTP-заголовка, если он задан, иначе пустая строка. Если задать значение <see langword="null"/> или пустую строку, то HTTP-заголовок будет удалён из списка.</value>
        /// <exception cref="System.ArgumentException">Установка значения HTTP-заголовка, который должен задаваться с помощью специального свойства/метода.</exception>
        /// <remarks>Список HTTP-заголовков, которые должны задаваться только с помощью специальных свойств/методов:
        /// <list type="table">
        ///     <item>
        ///        <description>Accept-Encoding</description>
        ///     </item>
        ///     <item>
        ///        <description>Content-Length</description>
        ///     </item>
        ///     <item>
        ///         <description>Content-Type</description>
        ///     </item>
        ///     <item>
        ///        <description>Connection</description>
        ///     </item>
        ///     <item>
        ///        <description>Proxy-Connection</description>
        ///     </item>
        ///     <item>
        ///        <description>Host</description>
        ///     </item>
        /// </list>
        /// </remarks>
        public string this[HttpHeader header]
        {
            get => this[Http.Headers[header]];
            set => this[Http.Headers[header]] = value;
        }

        #endregion


        #region Конструкторы (открытые)

        /// <summary>
        /// Инициализирует новый экземпляр класса <see cref="HttpRequest"/>.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public HttpRequest()
        {
            Init();
        }
        
        static HttpRequest()
        {
            // It's a fix of HTTPs Proxies SSL issue
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback += ServerCertificateValidationCallback;
        }
        
        private static bool ServerCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslpolicyerrors)
        {
            return true;
        }

        /// <summary>
        /// Инициализирует новый экземпляр класса <see cref="HttpRequest"/>.
        /// </summary>
        /// <param name="baseAddress">Адрес интернет-ресурса, который используется, если в запросе указан относительный адрес.</param>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="baseAddress"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="baseAddress"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="baseAddress"/> не является абсолютным URI.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="baseAddress"/> не является абсолютным URI.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpRequest(string baseAddress)
        {
            #region Проверка параметров

            if (baseAddress == null)
                throw new ArgumentNullException(nameof(baseAddress));

            if (baseAddress.Length == 0)
                throw ExceptionHelper.EmptyString(nameof(baseAddress));

            #endregion

            if (!baseAddress.StartsWith("http"))
                baseAddress = "http://" + baseAddress;

            var uri = new Uri(baseAddress);

            if (!uri.IsAbsoluteUri)
                throw new ArgumentException(Resources.ArgumentException_OnlyAbsoluteUri, nameof(baseAddress));

            BaseAddress = uri;

            Init();
        }

        /// <summary>
        /// Инициализирует новый экземпляр класса <see cref="HttpRequest"/>.
        /// </summary>
        /// <param name="baseAddress">Адрес интернет-ресурса, который используется, если в запросе указан относительный адрес.</param>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="baseAddress"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="baseAddress"/> не является абсолютным URI.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpRequest(Uri baseAddress)
        {
            #region Проверка параметров

            if (baseAddress == null)
                throw new ArgumentNullException(nameof(baseAddress));

            if (!baseAddress.IsAbsoluteUri)
                throw new ArgumentException(Resources.ArgumentException_OnlyAbsoluteUri, nameof(baseAddress));

            #endregion

            BaseAddress = baseAddress;

            Init();
        }

        #endregion


        #region Методы (открытые)

        #region Get

        /// <summary>
        /// Отправляет GET-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="urlParams">Параметры URL-адреса, или значение <see langword="null"/>.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        public HttpResponse Get(string address, RequestParams urlParams = null)
        {
            // ReSharper disable once InvertIf
            if (urlParams != null)
            {
                var uriBuilder = new UriBuilder(address) {
                    Query = urlParams.Query
                };
                address = uriBuilder.Uri.AbsoluteUri;
            }

            return Raw(HttpMethod.GET, address);
        }

        /// <summary>
        /// Отправляет GET-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="urlParams">Параметры URL-адреса, или значение <see langword="null"/>.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Get(Uri address, RequestParams urlParams = null)
        {
            // ReSharper disable once InvertIf
            if (urlParams != null)
            {
                var uriBuilder = new UriBuilder(address) {
                    Query = urlParams.Query
                };
                address = uriBuilder.Uri;
            }

            return Raw(HttpMethod.GET, address);
        }

        #endregion


        #region Head

        /// <summary>
        /// Отправляет HEAD-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="urlParams">Параметры URL-адреса, или значение <see langword="null"/>.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        public HttpResponse Head(string address, RequestParams urlParams = null)
        {
            // ReSharper disable once InvertIf
            if (urlParams != null)
            {
                var uriBuilder = new UriBuilder(address) {
                    Query = urlParams.Query
                };
                address = uriBuilder.Uri.AbsoluteUri;
            }

            return Raw(HttpMethod.HEAD, address);
        }

        /// <summary>
        /// Отправляет HEAD-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="urlParams">Параметры URL-адреса, или значение <see langword="null"/>.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Head(Uri address, RequestParams urlParams = null)
        {
            // ReSharper disable once InvertIf
            if (urlParams != null)
            {
                var uriBuilder = new UriBuilder(address) {
                    Query = urlParams.Query
                };
                address = uriBuilder.Uri;
            }

            return Raw(HttpMethod.HEAD, address);
        }

        #endregion


        #region Options

        /// <summary>
        /// Отправляет OPTIONS-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="urlParams">Параметры URL-адреса, или значение <see langword="null"/>.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        public HttpResponse Options(string address, RequestParams urlParams = null)
        {
            // ReSharper disable once InvertIf
            if (urlParams != null)
            {
                var uriBuilder = new UriBuilder(address) {
                    Query = urlParams.Query
                };
                address = uriBuilder.Uri.AbsoluteUri;
            }

            return Raw(HttpMethod.OPTIONS, address);
        }

        /// <summary>
        /// Отправляет OPTIONS-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="urlParams">Параметры URL-адреса, или значение <see langword="null"/>.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Options(Uri address, RequestParams urlParams = null)
        {
            // ReSharper disable once InvertIf
            if (urlParams != null)
            {
                var uriBuilder = new UriBuilder(address) {
                    Query = urlParams.Query
                };
                address = uriBuilder.Uri;
            }

            return Raw(HttpMethod.OPTIONS, address);
        }

        #endregion


        #region Post

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(string address)
        {
            return Raw(HttpMethod.POST, address);
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(Uri address)
        {
            return Raw(HttpMethod.POST, address);
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="reqParams">Параметры запроса, отправляемые HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="reqParams"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(string address, RequestParams reqParams)
        {
            #region Проверка параметров

            if (reqParams == null)
                throw new ArgumentNullException(nameof(reqParams));

            #endregion

            return Raw(HttpMethod.POST, address, new FormUrlEncodedContent(reqParams));
        }


        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="reqParams">Параметры запроса, отправляемые HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="reqParams"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(Uri address, RequestParams reqParams)
        {
            #region Проверка параметров

            if (reqParams == null)
                throw new ArgumentNullException(nameof(reqParams));

            #endregion

            return Raw(HttpMethod.POST, address, new FormUrlEncodedContent(reqParams));
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="str">Строка, отправляемая HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="str"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="str"/> является пустой строкой.
        /// -или
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(string address, string str, string contentType)
        {
            #region Проверка параметров

            if (str == null)
                throw new ArgumentNullException(nameof(str));

            if (str.Length == 0)
                throw new ArgumentNullException(nameof(str));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StringContent(str) {
                ContentType = contentType
            };

            return Raw(HttpMethod.POST, address, content);
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="str">Строка, отправляемая HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="str"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="str"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(Uri address, string str, string contentType)
        {
            #region Проверка параметров

            if (str == null)
                throw new ArgumentNullException(nameof(str));

            if (str.Length == 0)
                throw new ArgumentNullException(nameof(str));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StringContent(str) {
                ContentType = contentType
            };

            return Raw(HttpMethod.POST, address, content);
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="bytes">Массив байтов, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="bytes"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(string address, byte[] bytes, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new BytesContent(bytes) {
                ContentType = contentType
            };

            return Raw(HttpMethod.POST, address, content);
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="bytes">Массив байтов, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="bytes"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="contentType"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(Uri address, byte[] bytes, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            var content = new BytesContent(bytes) {
                ContentType = contentType
            };

            return Raw(HttpMethod.POST, address, content);
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="stream">Поток данных, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="stream"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(string address, Stream stream, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StreamContent(stream) {
                ContentType = contentType
            };

            return Raw(HttpMethod.POST, address, content);
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="stream">Поток данных, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="stream"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="contentType"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(Uri address, Stream stream, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StreamContent(stream) {
                ContentType = contentType
            };

            return Raw(HttpMethod.POST, address, content);
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="path">Путь к файлу, данные которого будут отправлены HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="path"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="path"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(string address, string path)
        {
            #region Проверка параметров

            if (path == null)
                throw new ArgumentNullException(nameof(path));

            if (path.Length == 0)
                throw new ArgumentNullException(nameof(path));

            #endregion

            return Raw(HttpMethod.POST, address, new FileContent(path));
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="path">Путь к файлу, данные которого будут отправлены HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="path"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="path"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(Uri address, string path)
        {
            #region Проверка параметров

            if (path == null)
                throw new ArgumentNullException(nameof(path));

            if (path.Length == 0)
                throw new ArgumentNullException(nameof(path));

            #endregion

            return Raw(HttpMethod.POST, address, new FileContent(path));
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="content">Контент, отправляемый HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="content"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(string address, HttpContent content)
        {
            #region Проверка параметров

            if (content == null)
                throw new ArgumentNullException(nameof(content));

            #endregion

            return Raw(HttpMethod.POST, address, content);
        }

        /// <summary>
        /// Отправляет POST-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="content">Контент, отправляемый HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="content"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Post(Uri address, HttpContent content)
        {
            #region Проверка параметров

            if (content == null)
                throw new ArgumentNullException(nameof(content));

            #endregion

            return Raw(HttpMethod.POST, address, content);
        }

        #endregion

        #region Raw

        /// <summary>
        /// Отправляет запрос HTTP-серверу.
        /// </summary>
        /// <param name="method">HTTP-метод запроса.</param>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="content">Контент, отправляемый HTTP-серверу, или значение <see langword="null"/>.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Raw(HttpMethod method, string address, HttpContent content = null)
        {
            #region Проверка параметров

            if (address == null)
                throw new ArgumentNullException(nameof(address));

            if (address.Length == 0)
                throw ExceptionHelper.EmptyString(nameof(address));

            #endregion

            var uri = new Uri(address, UriKind.RelativeOrAbsolute);
            return Raw(method, uri, content);
        }

        /// <summary>
        /// Отправляет запрос HTTP-серверу.
        /// </summary>
        /// <param name="method">HTTP-метод запроса.</param>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="content">Контент, отправляемый HTTP-серверу, или значение <see langword="null"/>.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        public HttpResponse Raw(HttpMethod method, Uri address, HttpContent content = null)
        {
            #region Проверка параметров

            if (address == null)
                throw new ArgumentNullException(nameof(address));

            #endregion

            if (!address.IsAbsoluteUri)
                address = GetRequestAddress(BaseAddress, address);

            if (content == null)
            {
                if (_temporaryMultipartContent != null)
                    content = _temporaryMultipartContent;
            }

            try
            {
                return Request(method, address, content);
            }
            finally
            {
                content?.Dispose();

                ClearRequestData(false);
            }
        }

        #endregion

        #region Добавление временных данных запроса

        /// <summary>
        /// Добавляет временный HTTP-заголовок запроса. Такой заголовок перекрывает заголовок установленный через индексатор.
        /// </summary>
        /// <param name="name">Имя HTTP-заголовка.</param>
        /// <param name="value">Значение HTTP-заголовка.</param>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="name"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="value"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="name"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="value"/> является пустой строкой.
        /// -или-
        /// Установка значения HTTP-заголовка, который должен задаваться с помощью специального свойства/метода.
        /// </exception>
        /// <remarks>Данный HTTP-заголовок будет стёрт после первого запроса.</remarks>
        public HttpRequest AddHeader(string name, string value)
        {
            #region Проверка параметров

            if (name == null)
                throw new ArgumentNullException(nameof(name));

            if (name.Length == 0)
                throw ExceptionHelper.EmptyString(nameof(name));

            if (value == null)
                throw new ArgumentNullException(nameof(value));

            if (value.Length == 0 && !AllowEmptyHeaderValues)
                throw ExceptionHelper.EmptyString(nameof(value));

            #endregion

            if (_temporaryHeaders == null)
            {
                _temporaryHeaders = new Dictionary<string, string>();
            }

            _temporaryHeaders[name] = value;

            return this;
        }

        /// <summary>
        /// Добавляет заголовок "X-Requested-With" со значением "XMLHttpRequest".
        /// Применяется к AJAX запросам.
        /// </summary>
        /// <returns>Вернет тот же HttpRequest для цепочки вызовов (pipeline).</returns>
        // ReSharper disable once UnusedMember.Global
        public HttpRequest AddXmlHttpRequestHeader()
        {
            return AddHeader("X-Requested-With", "XMLHttpRequest");
        }

        /// <summary>
        /// Добавляет временный HTTP-заголовок запроса. Такой заголовок перекрывает заголовок установленный через индексатор.
        /// </summary>
        /// <param name="header">HTTP-заголовок.</param>
        /// <param name="value">Значение HTTP-заголовка.</param>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="value"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="value"/> является пустой строкой.
        /// -или-
        /// Установка значения HTTP-заголовка, который должен задаваться с помощью специального свойства/метода.
        /// </exception>
        /// <remarks>Данный HTTP-заголовок будет стёрт после первого запроса.</remarks>
        // ReSharper disable once UnusedMethodReturnValue.Global
        public HttpRequest AddHeader(HttpHeader header, string value)
        {
            AddHeader(Http.Headers[header], value);

            return this;
        }

        #endregion

        /// <summary>
        /// Закрывает соединение с HTTP-сервером.
        /// </summary>
        /// <remarks>Вызов данного метода равносилен вызову метода <see cref="Dispose()"/>.</remarks>
        // ReSharper disable once UnusedMember.Global
        public void Close()
        {
            Dispose();
        }

        /// <inheritdoc />
        /// <summary>
        /// Освобождает все ресурсы, используемые текущим экземпляром класса <see cref="Leaf.xNet.HttpRequest" />.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        /// Определяет, содержатся ли указанные куки.
        /// </summary>
        /// <param name="url">Адрес ресурса</param>
        /// <param name="name">Название куки.</param>
        /// <returns>Значение <see langword="true"/>, если указанные куки содержатся, иначе значение <see langword="false"/>.</returns>
        // ReSharper disable once UnusedMember.Global
        public bool ContainsCookie(string url, string name)
        {
            return UseCookies && Cookies != null && Cookies.Contains(url, name);
        }

        #region Работа с заголовками

        /// <summary>
        /// Определяет, содержится ли указанный HTTP-заголовок.
        /// </summary>
        /// <param name="headerName">Название HTTP-заголовка.</param>
        /// <returns>Значение <see langword="true"/>, если указанный HTTP-заголовок содержится, иначе значение <see langword="false"/>.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="headerName"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="headerName"/> является пустой строкой.</exception>
        public bool ContainsHeader(string headerName)
        {
            #region Проверка параметров

            if (headerName == null)
                throw new ArgumentNullException(nameof(headerName));

            if (headerName.Length == 0)
                throw ExceptionHelper.EmptyString(nameof(headerName));

            #endregion

            return _permanentHeaders.ContainsKey(headerName);
        }

        /// <summary>
        /// Определяет, содержится ли указанный HTTP-заголовок.
        /// </summary>
        /// <param name="header">HTTP-заголовок.</param>
        /// <returns>Значение <see langword="true"/>, если указанный HTTP-заголовок содержится, иначе значение <see langword="false"/>.</returns>
        // ReSharper disable once UnusedMember.Global
        public bool ContainsHeader(HttpHeader header)
        {
            return ContainsHeader(Http.Headers[header]);
        }

        /// <summary>
        /// Возвращает перечисляемую коллекцию HTTP-заголовков.
        /// </summary>
        /// <returns>Коллекция HTTP-заголовков.</returns>
        // ReSharper disable once UnusedMember.Global
        public Dictionary<string, string>.Enumerator EnumerateHeaders()
        {
            return _permanentHeaders.GetEnumerator();
        }

        /// <summary>
        /// Очищает все постоянные HTTP-заголовки.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public void ClearAllHeaders() => _permanentHeaders.Clear();

        #endregion

        #endregion


        #region Patch

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(string address)
        {
            return Raw(HttpMethod.PATCH, address);
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(Uri address)
        {
            return Raw(HttpMethod.PATCH, address);
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="reqParams">Параметры запроса, отправляемые HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="reqParams"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(string address, RequestParams reqParams)
        {
            #region Проверка параметров

            if (reqParams == null)
                throw new ArgumentNullException(nameof(reqParams));

            #endregion

            return Raw(HttpMethod.PATCH, address, new FormUrlEncodedContent(reqParams));
        }


        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="reqParams">Параметры запроса, отправляемые HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="reqParams"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(Uri address, RequestParams reqParams)
        {
            #region Проверка параметров

            if (reqParams == null)
                throw new ArgumentNullException(nameof(reqParams));

            #endregion

            return Raw(HttpMethod.PATCH, address, new FormUrlEncodedContent(reqParams));
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="str">Строка, отправляемая HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="str"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="str"/> является пустой строкой.
        /// -или
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(string address, string str, string contentType)
        {
            #region Проверка параметров

            if (str == null)
                throw new ArgumentNullException(nameof(str));

            if (str.Length == 0)
                throw new ArgumentNullException(nameof(str));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StringContent(str) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PATCH, address, content);
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="str">Строка, отправляемая HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="str"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="str"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(Uri address, string str, string contentType)
        {
            #region Проверка параметров

            if (str == null)
                throw new ArgumentNullException(nameof(str));

            if (str.Length == 0)
                throw new ArgumentNullException(nameof(str));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StringContent(str) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PATCH, address, content);
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="bytes">Массив байтов, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="bytes"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(string address, byte[] bytes, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new BytesContent(bytes) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PATCH, address, content);
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="bytes">Массив байтов, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="bytes"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="contentType"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(Uri address, byte[] bytes, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            var content = new BytesContent(bytes) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PATCH, address, content);
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="stream">Поток данных, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="stream"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(string address, Stream stream, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StreamContent(stream) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PATCH, address, content);
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="stream">Поток данных, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="stream"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="contentType"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(Uri address, Stream stream, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StreamContent(stream) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PATCH, address, content);
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="path">Путь к файлу, данные которого будут отправлены HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="path"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="path"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(string address, string path)
        {
            #region Проверка параметров

            if (path == null)
                throw new ArgumentNullException(nameof(path));

            if (path.Length == 0)
                throw new ArgumentNullException(nameof(path));

            #endregion

            return Raw(HttpMethod.PATCH, address, new FileContent(path));
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="path">Путь к файлу, данные которого будут отправлены HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="path"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="path"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(Uri address, string path)
        {
            #region Проверка параметров

            if (path == null)
                throw new ArgumentNullException(nameof(path));

            if (path.Length == 0)
                throw new ArgumentNullException(nameof(path));

            #endregion

            return Raw(HttpMethod.PATCH, address, new FileContent(path));
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="content">Контент, отправляемый HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="content"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(string address, HttpContent content)
        {
            #region Проверка параметров

            if (content == null)
                throw new ArgumentNullException(nameof(content));

            #endregion

            return Raw(HttpMethod.PATCH, address, content);
        }

        /// <summary>
        /// Отправляет PATCH-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="content">Контент, отправляемый HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="content"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Patch(Uri address, HttpContent content)
        {
            #region Проверка параметров

            if (content == null)
                throw new ArgumentNullException(nameof(content));

            #endregion

            return Raw(HttpMethod.PATCH, address, content);
        }

        #endregion

        
        #endregion


        #region Put

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(string address)
        {
            return Raw(HttpMethod.PUT, address);
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(Uri address)
        {
            return Raw(HttpMethod.PUT, address);
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="reqParams">Параметры запроса, отправляемые HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="reqParams"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(string address, RequestParams reqParams)
        {
            #region Проверка параметров

            if (reqParams == null)
                throw new ArgumentNullException(nameof(reqParams));

            #endregion

            return Raw(HttpMethod.PUT, address, new FormUrlEncodedContent(reqParams));
        }


        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="reqParams">Параметры запроса, отправляемые HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="reqParams"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(Uri address, RequestParams reqParams)
        {
            #region Проверка параметров

            if (reqParams == null)
                throw new ArgumentNullException(nameof(reqParams));

            #endregion

            return Raw(HttpMethod.PUT, address, new FormUrlEncodedContent(reqParams));
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="str">Строка, отправляемая HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="str"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="str"/> является пустой строкой.
        /// -или
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(string address, string str, string contentType)
        {
            #region Проверка параметров

            if (str == null)
                throw new ArgumentNullException(nameof(str));

            if (str.Length == 0)
                throw new ArgumentNullException(nameof(str));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StringContent(str) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PUT, address, content);
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="str">Строка, отправляемая HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="str"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="str"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(Uri address, string str, string contentType)
        {
            #region Проверка параметров

            if (str == null)
                throw new ArgumentNullException(nameof(str));

            if (str.Length == 0)
                throw new ArgumentNullException(nameof(str));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StringContent(str) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PUT, address, content);
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="bytes">Массив байтов, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="bytes"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(string address, byte[] bytes, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new BytesContent(bytes) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PUT, address, content);
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="bytes">Массив байтов, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="bytes"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="contentType"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(Uri address, byte[] bytes, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            var content = new BytesContent(bytes) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PUT, address, content);
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="stream">Поток данных, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="stream"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(string address, Stream stream, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StreamContent(stream) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PUT, address, content);
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="stream">Поток данных, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="stream"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="contentType"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(Uri address, Stream stream, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StreamContent(stream) {
                ContentType = contentType
            };

            return Raw(HttpMethod.PUT, address, content);
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="path">Путь к файлу, данные которого будут отправлены HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="path"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="path"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(string address, string path)
        {
            #region Проверка параметров

            if (path == null)
                throw new ArgumentNullException(nameof(path));

            if (path.Length == 0)
                throw new ArgumentNullException(nameof(path));

            #endregion

            return Raw(HttpMethod.PUT, address, new FileContent(path));
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="path">Путь к файлу, данные которого будут отправлены HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="path"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="path"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(Uri address, string path)
        {
            #region Проверка параметров

            if (path == null)
                throw new ArgumentNullException(nameof(path));

            if (path.Length == 0)
                throw new ArgumentNullException(nameof(path));

            #endregion

            return Raw(HttpMethod.PUT, address, new FileContent(path));
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="content">Контент, отправляемый HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="content"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(string address, HttpContent content)
        {
            #region Проверка параметров

            if (content == null)
                throw new ArgumentNullException(nameof(content));

            #endregion

            return Raw(HttpMethod.PUT, address, content);
        }

        /// <summary>
        /// Отправляет PUT-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="content">Контент, отправляемый HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="content"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Put(Uri address, HttpContent content)
        {
            #region Проверка параметров

            if (content == null)
                throw new ArgumentNullException(nameof(content));

            #endregion

            return Raw(HttpMethod.PUT, address, content);
        }

        #endregion
        
        #endregion


        #region Delete

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(string address)
        {
            return Raw(HttpMethod.DELETE, address);
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="address"/> равно <see langword="null"/>.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(Uri address)
        {
            return Raw(HttpMethod.DELETE, address);
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="reqParams">Параметры запроса, отправляемые HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="reqParams"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(string address, RequestParams reqParams)
        {
            #region Проверка параметров

            if (reqParams == null)
                throw new ArgumentNullException(nameof(reqParams));

            #endregion

            return Raw(HttpMethod.DELETE, address, new FormUrlEncodedContent(reqParams));
        }


        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="reqParams">Параметры запроса, отправляемые HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="reqParams"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(Uri address, RequestParams reqParams)
        {
            #region Проверка параметров

            if (reqParams == null)
                throw new ArgumentNullException(nameof(reqParams));

            #endregion

            return Raw(HttpMethod.DELETE, address, new FormUrlEncodedContent(reqParams));
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="str">Строка, отправляемая HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="str"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="str"/> является пустой строкой.
        /// -или
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(string address, string str, string contentType)
        {
            #region Проверка параметров

            if (str == null)
                throw new ArgumentNullException(nameof(str));

            if (str.Length == 0)
                throw new ArgumentNullException(nameof(str));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StringContent(str) {
                ContentType = contentType
            };

            return Raw(HttpMethod.DELETE, address, content);
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="str">Строка, отправляемая HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="str"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="str"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(Uri address, string str, string contentType)
        {
            #region Проверка параметров

            if (str == null)
                throw new ArgumentNullException(nameof(str));

            if (str.Length == 0)
                throw new ArgumentNullException(nameof(str));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StringContent(str) {
                ContentType = contentType
            };

            return Raw(HttpMethod.DELETE, address, content);
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="bytes">Массив байтов, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="bytes"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(string address, byte[] bytes, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new BytesContent(bytes) {
                ContentType = contentType
            };

            return Raw(HttpMethod.DELETE, address, content);
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="bytes">Массив байтов, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="bytes"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="contentType"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(Uri address, byte[] bytes, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            var content = new BytesContent(bytes) {
                ContentType = contentType
            };

            return Raw(HttpMethod.DELETE, address, content);
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="stream">Поток данных, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="stream"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(string address, Stream stream, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StreamContent(stream) {
                ContentType = contentType
            };

            return Raw(HttpMethod.DELETE, address, content);
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="stream">Поток данных, отправляемый HTTP-серверу.</param>
        /// <param name="contentType">Тип отправляемых данных.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="stream"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="contentType"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="contentType"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(Uri address, Stream stream, string contentType = "application/octet-stream")
        {
            #region Проверка параметров

            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (contentType == null)
                throw new ArgumentNullException(nameof(contentType));

            if (contentType.Length == 0)
                throw new ArgumentNullException(nameof(contentType));

            #endregion

            var content = new StreamContent(stream) {
                ContentType = contentType
            };

            return Raw(HttpMethod.DELETE, address, content);
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="path">Путь к файлу, данные которого будут отправлены HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="path"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">
        /// Значение параметра <paramref name="address"/> является пустой строкой.
        /// -или-
        /// Значение параметра <paramref name="path"/> является пустой строкой.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(string address, string path)
        {
            #region Проверка параметров

            if (path == null)
                throw new ArgumentNullException(nameof(path));

            if (path.Length == 0)
                throw new ArgumentNullException(nameof(path));

            #endregion

            return Raw(HttpMethod.DELETE, address, new FileContent(path));
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="path">Путь к файлу, данные которого будут отправлены HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="path"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="path"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(Uri address, string path)
        {
            #region Проверка параметров

            if (path == null)
                throw new ArgumentNullException(nameof(path));

            if (path.Length == 0)
                throw new ArgumentNullException(nameof(path));

            #endregion

            return Raw(HttpMethod.DELETE, address, new FileContent(path));
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="content">Контент, отправляемый HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="content"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="address"/> является пустой строкой.</exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(string address, HttpContent content)
        {
            #region Проверка параметров

            if (content == null)
                throw new ArgumentNullException(nameof(content));

            #endregion

            return Raw(HttpMethod.DELETE, address, content);
        }

        /// <summary>
        /// Отправляет DELETE-запрос HTTP-серверу.
        /// </summary>
        /// <param name="address">Адрес интернет-ресурса.</param>
        /// <param name="content">Контент, отправляемый HTTP-серверу.</param>
        /// <returns>Объект, предназначенный для загрузки ответа от HTTP-сервера.</returns>
        /// <exception cref="System.ArgumentNullException">
        /// Значение параметра <paramref name="address"/> равно <see langword="null"/>.
        /// -или-
        /// Значение параметра <paramref name="content"/> равно <see langword="null"/>.
        /// </exception>
        /// <exception cref="Leaf.xNet.HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public HttpResponse Delete(Uri address, HttpContent content)
        {
            #region Проверка параметров

            if (content == null)
                throw new ArgumentNullException(nameof(content));

            #endregion

            return Raw(HttpMethod.DELETE, address, content);
        }

        #endregion
        
        #endregion

        #endregion
        
        #region Методы (защищённые)

        /// <summary>
        /// Освобождает неуправляемые (а при необходимости и управляемые) ресурсы, используемые объектом <see cref="HttpRequest"/>.
        /// </summary>
        /// <param name="disposing">Значение <see langword="true"/> позволяет освободить управляемые и неуправляемые ресурсы; значение <see langword="false"/> позволяет освободить только неуправляемые ресурсы.</param>
        private void Dispose(bool disposing)
        {
            if (!disposing || TcpClient == null)
                return;

            TcpClient?.Close();
            TcpClient = null;

            if (RequestSslProvider.Disposable)
            {
                ClientStream?.Dispose();
                ClientStream = null;

                ClientNetworkStream?.Dispose();
                ClientNetworkStream = null;
            }

            _keepAliveRequestCount = 0;
        }

        /// <summary>
        /// Вызывает событие <see cref="UploadProgressChanged"/>.
        /// </summary>
        /// <param name="e">Аргументы события.</param>
        private void OnUploadProgressChanged(UploadProgressChangedEventArgs e)
        {
            var eventHandler = _uploadProgressChangedHandler;

            eventHandler?.Invoke(this, e);
        }

        /// <summary>
        /// Вызывает событие <see cref="DownloadProgressChanged"/>.
        /// </summary>
        /// <param name="e">Аргументы события.</param>
        private void OnDownloadProgressChanged(DownloadProgressChangedEventArgs e)
        {
            var eventHandler = _downloadProgressChangedHandler;

            eventHandler?.Invoke(this, e);
        }

        #endregion

        #region Методы (закрытые)

        private void Init()
        {
            KeepAlive = true;
            AllowAutoRedirect = true;
            _tempAllowAutoRedirect = AllowAutoRedirect;

            EnableEncodingContent = true;

            Response = new HttpResponse(this);
        }

        private static Uri GetRequestAddress(Uri baseAddress, Uri address)
        {
            Uri requestAddress;

            if (baseAddress == null)
            {
                var uriBuilder = new UriBuilder(address.OriginalString);
                requestAddress = uriBuilder.Uri;
            }
            else
                Uri.TryCreate(baseAddress, address, out requestAddress);

            return requestAddress;
        }

        #region Отправка запроса

        private HttpResponse Request(HttpMethod method, Uri address, HttpContent content)
        {
            while (true)
            {
                _method = method;
                _content = content;

                CloseConnectionIfNeeded();

                var previousAddress = Address;
                Address = address;

                bool createdNewConnection;
                try
                {
                    createdNewConnection = TryCreateConnectionOrUseExisting(address, previousAddress);
                }
                catch (HttpException)
                {
                    if (CanReconnect)
                        return ReconnectAfterFail();

                    throw;
                }

                if (createdNewConnection)
                    _keepAliveRequestCount = 1;
                else
                    _keepAliveRequestCount++;

                #region Отправка запроса

                try
                {
                    SendRequestData(address, method);
                }
                catch (SecurityException ex)
                {
                    throw NewHttpException(Resources.HttpException_FailedSendRequest, ex,
                        HttpExceptionStatus.SendFailure);
                }
                catch (IOException ex)
                {
                    if (CanReconnect)
                        return ReconnectAfterFail();

                    throw NewHttpException(Resources.HttpException_FailedSendRequest, ex,
                        HttpExceptionStatus.SendFailure);
                }

                #endregion

                #region Загрузка заголовков ответа

                try
                {
                    ReceiveResponseHeaders(method);
                }
                catch (HttpException ex)
                {
                    if (CanReconnect)
                        return ReconnectAfterFail();

                    // Если сервер оборвал постоянное соединение вернув пустой ответ, то пробуем подключиться заново.
                    // Он мог оборвать соединение потому, что достигнуто максимально допустимое кол-во запросов или вышло время простоя.
                    if (KeepAlive && !_keepAliveReconnected && !createdNewConnection && ex.EmptyMessageBody)
                        return KeepAliveReconnect();

                    throw;
                }

                #endregion

                Response.ReconnectCount = _reconnectCount;

                _reconnectCount = 0;
                _keepAliveReconnected = false;
                _whenConnectionIdle = DateTime.Now;

                if (!IgnoreProtocolErrors)
                    CheckStatusCode(Response.StatusCode);

                #region Переадресация

                if (AllowAutoRedirect && Response.HasRedirect)
                {
                    if (++_redirectionCount > _maximumAutomaticRedirections)
                        throw NewHttpException(Resources.HttpException_LimitRedirections);

                    if (Response.HasExternalRedirect)
                        return Response;

                    ClearRequestData(true);

                    method = HttpMethod.GET;
                    address = Response.RedirectAddress;
                    content = null;
                    continue;
                }

                _redirectionCount = 0;

                #endregion

                return Response;
            }
        }

        private void CloseConnectionIfNeeded()
        {
            bool hasConnection = TcpClient != null && ClientStream != null;

            if (!hasConnection || Response.HasError || Response.MessageBodyLoaded)
                return;

            try
            {
                Response.None();
            }
            catch (HttpException)
            {
                Dispose();
            }
        }

        private bool TryCreateConnectionOrUseExisting(Uri address, Uri previousAddress)
        {
            var proxy = GetProxy();

            bool hasConnection = TcpClient != null;
            bool proxyChanged = !Equals(_currentProxy, proxy);

            bool addressChanged =
                previousAddress == null ||
                previousAddress.Port != address.Port ||
                previousAddress.Host != address.Host ||
                previousAddress.Scheme != address.Scheme;

            // Fix by Igor Vacil'ev
            bool connectionClosedByServer = Response.ContainsHeader("Connection") && Response["Connection"] == "close";

            // Если нужно создать новое подключение.
            if (hasConnection && !proxyChanged && !addressChanged && !Response.HasError &&
                !KeepAliveLimitIsReached() && !connectionClosedByServer)
                return false;

            _currentProxy = proxy;

            Dispose();
            CreateConnection(address);
            return true;
        }

        private bool KeepAliveLimitIsReached()
        {
            if (!KeepAlive)
                return false;

            int maximumKeepAliveRequests =
                Response.MaximumKeepAliveRequests ?? _maximumKeepAliveRequests;

            if (_keepAliveRequestCount >= maximumKeepAliveRequests)
                return true;

            int keepAliveTimeout = Response.KeepAliveTimeout ?? _keepAliveTimeout;

            var timeLimit = _whenConnectionIdle.AddMilliseconds(keepAliveTimeout);

            return timeLimit < DateTime.Now;
        }

        private void SendRequestData(Uri uri, HttpMethod method)
        {
            long contentLength = 0L;
            string contentType = string.Empty;

            if (CanContainsRequestBody(method) && _content != null)
            {
                contentType = _content.ContentType;
                contentLength = _content.CalculateContentLength();
            }


            string startingLine = GenerateStartingLine(method);
            string headers = GenerateHeaders(uri, method, contentLength, contentType);

            var startingLineBytes = Encoding.ASCII.GetBytes(startingLine);
            var headersBytes = Encoding.ASCII.GetBytes(headers);

            _bytesSent = 0;
            _totalBytesSent = startingLineBytes.Length + headersBytes.Length + contentLength;

            ClientStream.Write(startingLineBytes, 0, startingLineBytes.Length);
            ClientStream.Write(headersBytes, 0, headersBytes.Length);

            bool hasRequestBody = _content != null && contentLength > 0;

            // Отправляем тело запроса, если оно не присутствует.
            if (hasRequestBody)
                _content.WriteTo(ClientStream);
        }

        private void ReceiveResponseHeaders(HttpMethod method)
        {
            _canReportBytesReceived = false;

            _bytesReceived = 0;
            _totalBytesReceived = Response.LoadResponse(method, EnableMiddleHeaders);

            _canReportBytesReceived = true;
        }

        private bool CanReconnect => Reconnect && _reconnectCount < _reconnectLimit;

        private HttpResponse ReconnectAfterFail()
        {
            Dispose();
            Thread.Sleep(_reconnectDelay);

            _reconnectCount++;
            return Request(_method, Address, _content);
        }

        private HttpResponse KeepAliveReconnect()
        {
            Dispose();
            _keepAliveReconnected = true;
            return Request(_method, Address, _content);
        }

        private void CheckStatusCode(HttpStatusCode statusCode)
        {
            int statusCodeNum = (int) statusCode;

            if (statusCodeNum >= 400 && statusCodeNum < 500)
            {
                throw new HttpException(string.Format(
                        Resources.HttpException_ClientError, statusCodeNum),
                    HttpExceptionStatus.ProtocolError, Response.StatusCode);
            }

            if (statusCodeNum >= 500)
            {
                throw new HttpException(string.Format(
                        Resources.HttpException_SeverError, statusCodeNum),
                    HttpExceptionStatus.ProtocolError, Response.StatusCode);
            }
        }

        private static bool CanContainsRequestBody(HttpMethod method)
        {
            return
                method == HttpMethod.POST ||
                method == HttpMethod.PUT ||
                method == HttpMethod.PATCH ||
                method == HttpMethod.DELETE;
        }

        #endregion

        #region Создание подключения

        private ProxyClient GetProxy()
        {
            if (!DisableProxyForLocalAddress)
                return Proxy ?? GlobalProxy;

            try
            {
                var checkIp = IPAddress.Parse("127.0.0.1");
                var ips = Dns.GetHostAddresses(Address.Host);

                // ReSharper disable once LoopCanBeConvertedToQuery
                foreach (var ip in ips)
                {
                    if (ip.Equals(checkIp))
                        return null;
                }
            }
            catch (Exception ex)
            {
                if (ex is SocketException || ex is ArgumentException)
                    throw NewHttpException(Resources.HttpException_FailedGetHostAddresses, ex);

                throw;
            }

            return Proxy ?? GlobalProxy;
        }

        private TcpClient CreateTcpConnection(string host, int port)
        {
            TcpClient tcpClient;

            if (_currentProxy == null)
            {
                #region Создание подключения

                tcpClient = new TcpClient();

                Exception connectException = null;
                var connectDoneEvent = new ManualResetEventSlim();

                try
                {
                    tcpClient.BeginConnect(host, port, ar => {
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
                    {
                        throw NewHttpException(Resources.HttpException_FailedConnect, ex,
                            HttpExceptionStatus.ConnectFailure);
                    }

                    throw;
                }

                #endregion

                if (!connectDoneEvent.Wait(_connectTimeout))
                {
                    tcpClient.Close();
                    throw NewHttpException(Resources.HttpException_ConnectTimeout, null,
                        HttpExceptionStatus.ConnectFailure);
                }

                if (connectException != null)
                {
                    tcpClient.Close();

                    if (connectException is SocketException)
                    {
                        throw NewHttpException(Resources.HttpException_FailedConnect, connectException,
                            HttpExceptionStatus.ConnectFailure);
                    }

                    throw connectException;
                }

                if (!tcpClient.Connected)
                {
                    tcpClient.Close();
                    throw NewHttpException(Resources.HttpException_FailedConnect, null,
                        HttpExceptionStatus.ConnectFailure);
                }

                #endregion

                tcpClient.SendTimeout = _readWriteTimeout;
                tcpClient.ReceiveTimeout = _readWriteTimeout;
            }
            else
            {
                try
                {
                    tcpClient = _currentProxy.CreateConnection(host, port);
                }
                catch (ProxyException ex)
                {
                    throw NewHttpException(Resources.HttpException_FailedConnect, ex,
                        HttpExceptionStatus.ConnectFailure);
                }
            }

            return tcpClient;
        }
        
        public SystemSslProvider SslProvider()
        {
            return SslProvider<SystemSslProvider>();
        }

        public T SslProvider<T>() where T: class, ISslProvider, new()
        {
            if (typeof(T) == RequestSslProvider.GetType())
                return RequestSslProvider as T;

            var sslProvider = new T();
            RequestSslProvider = sslProvider;
            return sslProvider;
        }

        private void CreateConnection(Uri address)
        {
            TcpClient = CreateTcpConnection(address.Host, address.Port);
            ClientNetworkStream = TcpClient.GetStream();

            // Если требуется безопасное соединение.
            if (address.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    ClientStream = RequestSslProvider.Initialize(address, ClientNetworkStream);
                }
                catch (Exception ex)
                {
                    if (ex is IOException || ex is AuthenticationException)
                    {
                        throw NewHttpException(Resources.HttpException_FailedSslConnect, ex,
                            HttpExceptionStatus.ConnectFailure);
                    }
                    throw;
                }
            }
            else
            {
                ClientStream = ClientNetworkStream;
            }

            if (_uploadProgressChangedHandler == null && _downloadProgressChangedHandler == null)
                return;

            var httpWrapperStream = new HttpWrapperStream(
                ClientStream, TcpClient.SendBufferSize);

            if (_uploadProgressChangedHandler != null)
                httpWrapperStream.BytesWriteCallback = ReportBytesSent;

            if (_downloadProgressChangedHandler != null)
                httpWrapperStream.BytesReadCallback = ReportBytesReceived;

            ClientStream = httpWrapperStream;
        }

        #endregion

        #region Формирование данных запроса

        private string GenerateStartingLine(HttpMethod method)
        {
            // Fix by Igor Vacil'ev: sometimes proxies returns 404 when used full path.
            bool hasHttpProxyWithAbsoluteUriInStartingLine = 
                _currentProxy != null &&
                _currentProxy.Type == ProxyType.HTTP &&
                _currentProxy.AbsoluteUriInStartingLine;

            string query = hasHttpProxyWithAbsoluteUriInStartingLine
                ? Address.AbsoluteUri
                : Address.PathAndQuery;

            return $"{method} {query} HTTP/{ProtocolVersion}\r\n";
        }


        //private string GenerateStartingLine(HttpMethod method) => $"{method} {Address.PathAndQuery} HTTP/{ProtocolVersion}\r\n";

        // Есть 3 типа заголовков, которые могут перекрываться другими. Вот порядок их установки:
        // - заголовки, которые задаются через специальные свойства, либо автоматически
        // - заголовки, которые задаются через индексатор
        // - временные заголовки, которые задаются через метод AddHeader
        private string GenerateHeaders(Uri uri, HttpMethod method, long contentLength = 0, string contentType = null)
        {
            var headers = GenerateCommonHeaders(method, contentLength, contentType);

            MergeHeaders(headers, _permanentHeaders);

            if (_temporaryHeaders != null && _temporaryHeaders.Count > 0)
                MergeHeaders(headers, _temporaryHeaders);

            // Disabled cookies
            if (!UseCookies)
                return ToHeadersString(headers);

            // Cookies isn't set now
            if (Cookies == null)
            {
                Cookies = new CookieStorage(ignoreInvalidCookie: IgnoreInvalidCookie);
                return ToHeadersString(headers);
            }

            // No Cookies or cookies is set via direct header
            if (Cookies.Count == 0 || headers.ContainsKey("Cookie"))
                return ToHeadersString(headers);

            // Cookies from storage
            string cookies = Cookies.GetCookieHeader(uri);
            if (!string.IsNullOrEmpty(cookies))
                headers["Cookie"] = cookies;

            return ToHeadersString(headers);
        }

        private Dictionary<string, string> GenerateCommonHeaders(HttpMethod method, long contentLength = 0,
            string contentType = null)
        {
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                ["Host"] = Address.IsDefaultPort ? Address.Host : $"{Address.Host}:{Address.Port}"
            };

            #region Connection и Authorization

            HttpProxyClient httpProxy = null;

            if (_currentProxy != null && _currentProxy.Type == ProxyType.HTTP)
                httpProxy = _currentProxy as HttpProxyClient;

            if (httpProxy != null)
            {
                headers["Proxy-Connection"] = KeepAlive ? "keep-alive" : "close";

                if (!string.IsNullOrEmpty(httpProxy.Username) ||
                    !string.IsNullOrEmpty(httpProxy.Password))
                {
                    headers["Proxy-Authorization"] = GetProxyAuthorizationHeader(httpProxy);
                }
            }
            else
                headers["Connection"] = KeepAlive ? "keep-alive" : "close";

            if (!string.IsNullOrEmpty(Username) || !string.IsNullOrEmpty(Password))
                headers["Authorization"] = GetAuthorizationHeader();

            #endregion

            #region Content

            if (EnableEncodingContent)
                headers["Accept-Encoding"] = AcceptEncoding;

            if (Culture != null)
                headers["Accept-Language"] = GetLanguageHeader();

            if (CharacterSet != null)
                headers["Accept-Charset"] = GetCharsetHeader();

            if (!CanContainsRequestBody(method))
                return headers;

            if (contentLength > 0)
                headers["Content-Type"] = contentType;

            headers["Content-Length"] = contentLength.ToString();

            #endregion

            return headers;
        }

        #region Работа с заголовками

        private string GetAuthorizationHeader()
        {
            string data = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{Username}:{Password}"));

            return $"Basic {data}";
        }

        private static string GetProxyAuthorizationHeader(ProxyClient httpProxy)
        {
            string data = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{httpProxy.Username}:{httpProxy.Password}"));

            return $"Basic {data}";
        }

        private string GetLanguageHeader()
        {
            string cultureName = Culture?.Name ?? CultureInfo.CurrentCulture.Name;

            return cultureName.StartsWith("en")
                ? cultureName
                : $"{cultureName},{cultureName.Substring(0, 2)};q=0.8,en-US;q=0.6,en;q=0.4";
        }

        private string GetCharsetHeader()
        {
            if (Equals(CharacterSet, Encoding.UTF8))
                return "utf-8;q=0.7,*;q=0.3";

            string charsetName = CharacterSet?.WebName ?? Encoding.Default.WebName;

            return $"{charsetName},utf-8;q=0.7,*;q=0.3";
        }

        private static void MergeHeaders(IDictionary<string, string> destination, Dictionary<string, string> source)
        {
            foreach (var sourceItem in source)
                destination[sourceItem.Key] = sourceItem.Value;
        }

        #endregion

        private string ToHeadersString(Dictionary<string, string> headers)
        {
            var headersBuilder = new StringBuilder();
            foreach (var header in headers)
            {
                if (header.Key != "Cookie" || CookieSingleHeader)
                {
                    headersBuilder.AppendFormat("{0}: {1}\r\n", header.Key, header.Value);
                    continue;
                }

                // Каждую Cookie в отдельный заголовок
                var cookies = header.Value.Split(new[] {"; "}, StringSplitOptions.None);
                foreach (string cookie in cookies)
                    headersBuilder.AppendFormat("Cookie: {0}\r\n", cookie);
            }

            headersBuilder.AppendLine();
            return headersBuilder.ToString();
        }

        #endregion

        // Сообщает о том, сколько байт было отправлено HTTP-серверу.
        private void ReportBytesSent(int bytesSent)
        {
            _bytesSent += bytesSent;

            OnUploadProgressChanged(
                new UploadProgressChangedEventArgs(_bytesSent, _totalBytesSent));
        }

        // Сообщает о том, сколько байт было принято от HTTP-сервера.
        private void ReportBytesReceived(int bytesReceived)
        {
            _bytesReceived += bytesReceived;

            if (_canReportBytesReceived)
            {
                OnDownloadProgressChanged(
                    new DownloadProgressChangedEventArgs(_bytesReceived, _totalBytesReceived));
            }
        }

        private void ClearRequestData(bool redirect)
        {
            _content = null;

            _temporaryMultipartContent = null;

            if (!redirect || !KeepTemporaryHeadersOnRedirect)
                _temporaryHeaders = null;
        }

        private HttpException NewHttpException(string message,
            Exception innerException = null, HttpExceptionStatus status = HttpExceptionStatus.Other)
        {
            return new HttpException(string.Format(message, Address.Host), status, HttpStatusCode.None, innerException);
        }

        #endregion
    }
}