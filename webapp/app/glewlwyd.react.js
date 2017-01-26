var Alert = ReactBootstrap.Alert;
var Button = ReactBootstrap.Button;
var Modal = ReactBootstrap.Modal;

$(function() {
  // Global lists
  var scopeList = [];
  var resourceList = [];
  var authorizationTypeList = [];
  
  // Config variables
  var access_token = "access_token";
  var access_token_expires = 3600;
  
  // tab menu
  $('#nav li a').click(function() {
    $('#nav li').removeClass();
    $(this).parent().addClass('active');
    if (!$(this).parent().hasClass('dropdown'))
      $(".navbar-collapse").collapse('hide');
  });

  // Parse query parameters
  function getQueryParams(qs) {
    qs = qs.split('+').join(' ');

    var params = {},
      tokens,
      re = /[#&]?([^=]+)=([^&]*)/g;

    while (tokens = re.exec(qs)) {
      params[decodeURIComponent(tokens[1])] = decodeURIComponent(tokens[2]);
    }

    return params;
  }
  
  // Get OAuth2 token
  var oauth = {
    access_token: false,
    client_id: "g_admin",
    redirect_uri: "../app/index.html",
    scope: "g_admin"
  }
  
  var currentUser = {loggedIn: false, name: "", email: ""};

  // Function that will be used on every API call
  function APIRequest (method, url, data) {
    return $.ajax({
      method: method,
      url: url,
      data: data,
      contentType: data?"application/json; charset=utf-8":null,
      headers: {"Authorization": "Bearer " + oauth.access_token}
    })
    .fail(function (error) {
      if (error.status === 401) {
        oauth.access_token = false;
        currentUser.loggedIn = false;
        ReactDOM.render(
          <LoginComponent user={currentUser} oauth={oauth} />,
          document.getElementById('LoginComponent')
        );
      }
    });
  }

  // Load all lists at startup
  function loadLists () {
    var promises = [
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/client/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/scope/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/resource/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/authorization/")
    ];
    
    $.when(promises)
    .then(function (results) {
      results[0].done(function (result) {
        ReactDOM.render(
          <UserTable users={result} oauth={oauth} />,
          document.getElementById('users')
        );
      });
      
      results[2].done(function (result) {
        scopeList = result;
      });
      
      results[3].done(function (result) {
        resourceList = result;
      });
      
      results[4].done(function (result) {
        authorizationTypeList = result;
        ReactDOM.render(
          <AuthorizationTypeList authTypeList={result} oauth={oauth} />,
          document.getElementById('authType')
        );
      });
    })
    .fail(function (error) {
      if (error.status === 401) {
        currentUser.loggedIn = false;
      }
    });
  }
  
  /**
   * User table management component
   */
  class UserTable extends React.Component {
    constructor(props) {
      super(props);
      this.state = {search: "", offset: 0, limit: 10, users: this.props.users};
      
      this.handleSearch = this.handleSearch.bind(this);
      this.handleChangeSearch = this.handleChangeSearch.bind(this);
      this.handleChangeLimit = this.handleChangeLimit.bind(this);
      this.handlePreviousPage = this.handlePreviousPage.bind(this);
      this.handleNextPage = this.handleNextPage.bind(this);
    }
    
    handleChangeSearch (event) {
      this.setState({search: event.target.value});
    }
    
    handleChangeLimit (event) {
      var limit = parseInt(event.target.value);
      var offset = this.state.offset;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {limit: limit};
      });
    }
    
    handlePreviousPage (event) {
      var limit = this.state.limit;
      var offset = this.state.offset-limit;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {offset: offset};
      });
    }
    
    handleNextPage (event) {
      var limit = this.state.limit;
      var offset = this.state.offset+limit;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {offset: offset};
      });
    }
    
    handleSearch (event) {
      this.runSearch(this.state.search, this.state.offset, this.state.limit);
      event.preventDefault();
    }
    
    runSearch (search, offset, limit) {
      var self = this;
      if (search) {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/?search=" + search + "&limit=" + limit + "&offset=" + offset)
        .done(function (result) {
          self.setState({
            users: result
          });
        })
        .fail(function (error) {
          $("#alertTitle").text("Search users");
          $("#alertBody").text("Error while searching users");
          $("#alertModal").modal();
        });
      } else {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + "?limit=" + limit + "&offset=" + offset)
        .done(function (result) {
          self.setState({
            users: result
          });
        })
        .fail(function (error) {
          $("#alertTitle").text("Search users");
          $("#alertBody").text("Error while searching users");
          $("#alertModal").modal();
        });
      }
    }

    render() {
      var rows = [];
      this.state.users.forEach(function(user) {
        rows.push(<UserRow user={user} key={user.login} />);
      });
      var previousOpts = {};
      if (this.state.offset === 0) {
        previousOpts["disabled"] = "disabled";
      }
      
      return (
        <div>
          <form onSubmit={this.handleSearch}>
            <div className="input-group row">
              <input type="text" className="form-control" placeholder="Search" value={this.state.search} onChange={this.handleChangeSearch}/>
              <div className="input-group-btn">
                <button className="btn btn-default" type="button" onClick={this.handleSearch}><i className="glyphicon glyphicon-search"></i></button>
                <Button className="btn btn-default" onClick={this.open}>
                  {this.state.icon}
                </Button>
              </div>
            </div>
          </form>
          <div className="row">
            <div className="col-md-3">
              <div className="input-group">
                <div className="input-group-btn">
                  <button className="btn btn-default" {...previousOpts} type="button" onClick={this.handlePreviousPage}><i className="icon-resize-small fa fa-chevron-left"></i></button>
                </div>
                <div>
                  <select className="form-control" onChange={this.handleChangeLimit} value={this.state.limit}>
                    <option value="10">10</option>
                    <option value="25">25</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                  </select>
                </div>
                <div className="input-group-btn">
                  <button className="btn btn-default" type="button" onClick={this.handleNextPage}><i className="icon-resize-small fa fa-chevron-right"></i></button>
                </div>
              </div>
            </div>
            <div className="col-md-9 text-right">
              <span className="text-center">{this.state.limit} results maximum, starting at result: {this.state.offset}</span>
            </div>
          </div>
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Source</th>
                <th>Login</th>
                <th>Name</th>
                <th>E-mail</th>
                <th>Scopes</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
          <UserModal add={this.state.addUser} scopeList={this.state.scopeList} user={this.state.currentUser}/>
        </div>
      );
    }
  }

  class UserRow extends React.Component {
    constructor(props) {
      super(props);
    }
    
    render() {
      return (
        <tr>
          <td>{this.props.user.source}</td>
          <td>{this.props.user.login}</td>
          <td>{this.props.user.name}</td>
          <td>{this.props.user.email}</td>
          <td>{this.props.user.scope.join(", ")}</td>
          <td>{this.props.user.enabled?"true":"false"}</td>
          <td>
            <div className="input-group">
              <div className="input-group-btn">
                <UserModal user={this.props.user} add={false} scopeList={scopeList} />
                <button type="button" className="btn btn-default" name="userDelete" id="userDelete" data-toggle="modal" data-target="#confirmModal">
                  <i className="fa fa-trash" aria-hidden="true"></i>
                </button>
              </div>
            </div>
          </td>
        </tr>
      );
    }
  }

  class UserModal extends React.Component {
    constructor(props) {
      super(props);
      this.state = {user: this.props.user, showModal: false, icon: this.props.add?(<i className="icon-resize-small fa fa-plus" aria-hidden="true"></i>):(<i className="icon-resize-small fa fa-pencil" aria-hidden="true"></i>), scopeList: this.props.scopeList};
      this.close = this.close.bind(this);
      this.open = this.open.bind(this);
      this.save = this.save.bind(this);
    }
    
    close() {
      this.setState({ showModal: false });
    }

    open() {
      this.setState({ showModal: true });
    }
    
    save() {
    }

    render() {
      var userScopeList = [];
      this.state.scopeList.forEach(function (scope) {
        console.log(scope);
        userScopeList.push(<option value={scope.name}>{scope.name}</option>)
      });
      return (
        <Modal show={this.state.showModal} onHide={this.close}>
          <Modal.Header closeButton>
            <Modal.Title>User</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="userSource">Source</label>
              </div>
              <div className="col-md-6">
                <select className="form-control" name="userSource" id="userSource">
                  <option value="ldap">LDAP</option>
                  <option value="database">Database</option>
                </select>
              </div>
            </div>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="userLogin">Login</label>
              </div>
              <div className="col-md-6">
                <input className="form-control" type="text" name="userLogin" id="userLogin" placeholder="User Login"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="userPassword">Password</label>
              </div>
              <div className="col-md-6">
                <input className="form-control" type="password" name="userPassword" id="userPassword" placeholder="User password"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="userPasswordConfirm">Confirm password</label>
              </div>
              <div className="col-md-6">
                <input className="form-control" type="password" name="userPasswordConfirm" id="userPasswordConfirm" placeholder="Confirm User password"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="userName">Name</label>
              </div>
              <div className="col-md-6">
                <input className="form-control" type="text" name="userName" id="userName" placeholder="Fullname"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="userEmail">Email</label>
              </div>
              <div className="col-md-6">
                <input className="form-control" type="text" name="userEmail" id="userEmail" placeholder="User e-mail"></input>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label htmlFor="userScope">Scopes</label>
              </div>
              <div className="col-md-6">
                <div className="input-group">
                  <select id="userScope" name="userScope" className="form-control">
                    {userScopeList}
                  </select>
                  <div className="input-group-btn ">
                    <button type="button" name="addScope" id="addScope" className="btn btn-default">
                      <i className="icon-resize-small fa fa-plus" aria-hidden="true"></i>
                    </button>
                  </div>
                </div>
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
              </div>
              <div className="col-md-6" id="userScopeValue">
              </div>
            </div>
            <div className="row top-buffer">
              <div className="col-md-6">
                <label>Enabled</label>
              </div>
              <div className="col-md-6">
                <input type="checkbox" name="userEnabled" id="userEnabled"/>
              </div>
            </div>
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={this.save}>Save</Button>
            <Button onClick={this.close}>Cancel</Button>
          </Modal.Footer>
        </Modal>
      );
    }
  };
  
  /**
   * Login/Logout button component
   */
  function LoginInformation (props) {
    return (
      <span>Hello {props.user.name}&nbsp;</span>
    );
  }

  function ConnectMessage (props) {
    return (
      <span>Please log in to the application&nbsp;</span>
    );
  }

  class LogoutButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleLogout = this.handleLogout.bind(this);
    }
    
    render() {
      return (<button type="button" className="btn btn-primary" onClick={this.handleLogout}>
        <i className="fa fa-sign-out" aria-hidden="true"></i>
        &nbsp;Log out
      </button>);
    }
    
    handleLogout() {
      this.props.oauth.access_token = false;
      $.removeCookie(access_token);
      this.props.user.loggedIn = false;
      ReactDOM.render(
        <LoginComponent user={this.props.user} oauth={this.props.oauth} />,
        document.getElementById('LoginComponent')
      );
    }
  }

  class LoginButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleLogin = this.handleLogin.bind(this);
    }
    
    render() {
      return (<button type="button" className="btn btn-primary" onClick={this.handleLogin}>
        <i className="fa fa-sign-in" aria-hidden="true"></i>
        &nbsp;Log in
      </button>);
    }
    
    handleLogin() {
      document.location = "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/auth?response_type=token&client_id="+this.props.oauth.client_id+"&redirect_uri="+this.props.oauth.redirect_uri+"&scope="+this.props.oauth.scope;
    }
  }

  function LoginComponent (props) {
    if (props.user.loggedIn) {
      return (
        <div>
          <LoginInformation user={props.user} oauth={props.oauth} />
          <LogoutButton user={props.user} oauth={props.oauth} />
        </div>
      );
    } else {
      return (
        <div>
          <ConnectMessage />
          <LoginButton oauth={props.oauth} />
        </div>
      );
    }
  }

  /**
   * Authentication type table management component
   */
  class AuthTypeEnableButton extends React.Component {
    constructor(props) {
      super(props);
      this.state = {enabled: this.props.authType.enabled};
      this.handleToggleAuthType = this.handleToggleAuthType.bind(this);
    }
    
    render() {
      if (this.state.enabled) {
        return <button type="button" className="btn btn-danger" onClick={this.handleToggleAuthType} >Disable</button>
      } else {
        return <button type="button" className="btn btn-success" onClick={this.handleToggleAuthType} >Enable</button>
      }
    }
    
    handleToggleAuthType () {
      var self = this;
      APIRequest("PUT","https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/authorization/" + this.props.authType.name, JSON.stringify({description: this.props.authType.description, enabled: !this.state.enabled}))
      .done(function (result) {
        self.setState(prevState => ({
          enabled: !prevState.enabled
        }));
      })
      .fail(function (error) {
        $("#alertTitle").text("Toggle authorization type");
        $("#alertBody").text("Error while changing authorization type");
        $("#alertModal").modal();
      });
    }
  }

  class AuthorizationType extends React.Component {
    constructor(props) {
      super(props);
    }
    
    render () {
      return (
        <tr>
          <td>
            <label>{this.props.authType.name}</label>
          </td>
          <td>
            {this.props.authType.description}
          </td>
          <td>
            <AuthTypeEnableButton authType={this.props.authType} oauth={this.props.oauth} />
          </td>
        </tr>
      );
    }
  }

  function AuthorizationTypeList (props) {
    var rows = [];
    props.authTypeList.forEach(function(authType) {
      rows.push(<AuthorizationType authType={authType} key={authType.name} oauth={props.oauth} />);
    });
    return (
      <div className="well">
        <table className="table table-hover table-responsive">
          <thead>
            <tr>
              <th>Name</th>
              <th>Description</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows}
          </tbody>
        </table>
      </div>
    );
  }
  
  /**
   * javscript core code
   */
  var params = getQueryParams(location.hash);

  /**
   * get access_token from url, or from cookie
   */
  if (params.access_token) {
    oauth.access_token = params.access_token;
    var expires = new Date();
    expires.setSeconds(expires.getSeconds() + access_token_expires);
    $.cookie(access_token, params.access_token, {expires: expires});
    document.location = "#";
  } else if ($.cookie(access_token)) {
    oauth.access_token = $.cookie(access_token);
  }

  /**
   * If an acces_token is present, use it to get all lists
   * if no access_token, display the login button
   */
  if (oauth.access_token) {
    APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/auth/user/")
    .then(function (result) {
      currentUser.loggedIn = true;
      currentUser.name = result.name;
      currentUser.email = result.email;
      loadLists();
    })
    .fail(function (error) {
      if (error.status === 401) {
        currentUser.loggedIn = false;
      }
    })
    .always(function () {
      ReactDOM.render(
        <LoginComponent user={currentUser} oauth={oauth} />,
        document.getElementById('LoginComponent')
      );
    });
  } else {
    ReactDOM.render(
      <LoginComponent user={currentUser} oauth={oauth} />,
      document.getElementById('LoginComponent')
    );
  }
  
});
