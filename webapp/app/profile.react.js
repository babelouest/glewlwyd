/**
 * 
 * Glewlwyd OAuth2 Authorization Server
 *
 * Web application for server resource management
 *
 * Copyright 2017 Nicolas Mora <mail@babelouest.org>
 * 
 * The front-end application is under MIT Licence (MIT)
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

var Button = ReactBootstrap.Button;
var Checkbox = ReactBootstrap.Checkbox;
var Modal = ReactBootstrap.Modal;

$(function() {

  /**
   * Web application parameters
   * Except for glewlwyd_server_url which I recommend to update, 
   * the other values are not to be modified if you didn't change
   * the default parameters values during the installation
   */
  var oauth = {
    glewlwyd_server_url: "../", /* Default value if the web app is hosted by the API server. For security, I recommend to put the absolute url, e.g. https://auth.domain.com/ */

    /**
     *
     * This will contain server config variables, do not modify it. 
     * Anyway, if you do modify it, it will be overwritten
     * 
     */
    api_prefix: ""
  };
  
  var profile = {};
  
  // Function that will be used on every API call
  function APIRequest (method, url, data) {
    return $.ajax({
      method: method,
      url: oauth.glewlwyd_server_url + oauth.api_prefix + url,
      data: JSON.stringify(data),
      contentType: data?"application/json; charset=utf-8":null
    });
  }

  /**
   * User details component
   */
  function UserDetails (props) {
    return (
      <div>
        <h2>{props.user.name}</h2>
        <div className="well">
          <div className="row">
            <div className="col-md-3">
              <label>Name</label>
            </div>
            <div className="col-md-3">
              {props.user.name}
            </div>
            <div className="col-md-3">
              <label>Email</label>
            </div>
            <div className="col-md-3">
              {props.user.email}
            </div>
          </div>
          <div className="row">
            <div className="col-md-3">
              <label>Login</label>
            </div>
            <div className="col-md-3">
              {props.user.login}
            </div>
            <div className="col-md-3">
              <label>Scopes</label>
            </div>
            <div className="col-md-3">
              {props.user.scope.join(", ")}
            </div>
          </div>
        </div>
      </div>
    );
  }
  
  function UserSessionRow (props) {
    return (
      <tr className={!props.session.enabled?"danger":""}>
        <td>{props.session.ip_source}</td>
        <td>{(new Date(props.session.issued_at*1000)).toLocaleString()}</td>
        <td>{(new Date(props.session.last_seen*1000)).toLocaleString()}</td>
        <td>{(new Date(props.session.expired_at*1000)).toLocaleString()}</td>
        <td>{String(props.session.enabled)}</td>
        <td>
        {props.session.enabled?<Button className="btn btn-default" onClick={(event) => props.openModal(props.session, event)} data-toggle="tooltip" title="Revoke session">
            <i className="fa fa-trash"></i>
          </Button>:''}
        </td>
      </tr>
    );
  }
  
  class UserSessionTable extends React.Component {
    constructor(props) {
      super(props);
      this.state = {sessionList: this.props.sessionList};
      this.refreshSessionList = this.refreshSessionList.bind(this);
      this.openConfirmModal = this.openConfirmModal.bind(this);
      this.closeConfirmModal = this.closeConfirmModal.bind(this);
      
      this.state = {sessionList: this.props.sessionList, currentSession: {}}
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({sessionList: nextProps.sessionList});
    }
    
    refreshSessionList (valid, offset, limit) {
      var self = this;
      APIRequest("GET", "/profile/session/?valid=" + (valid?valid:"") + "&offset=" + (offset?offset:"") + "&limit=" + (limit?limit:""))
      .then(function (result) {
        self.setState({sessionList: result});
      });
    }
    
    openConfirmModal (session, evt) {
      this.setState({currentSession: session});
      ReactDOM.render(
        <ConfirmModal show={true} title={"Disable session"} message={"Are you sure you want to disable this session?"} onClose={this.closeConfirmModal} />,
        document.getElementById('modal')
      );
    }
    
    closeConfirmModal (result, evt) {
      var self = this;
      if (result) {
        APIRequest("DELETE", "/profile/session/", {session_hash: this.state.currentSession.session_hash})
        .then(function (result) {
          var currentSession = self.state.currentSession;
          currentSession.enabled = false;
          var sessionList = self.state.sessionList;
          sessionList.forEach(function (session) {
            if (session.session_hash === self.state.currentSession.session_hash) {
              session.enabled = false;
            }
          });
          self.setState({currentSession: currentSession, sessionList: sessionList});
          ReactDOM.render(
            <MessageModal show={true} title={"Session disabled"} message={"The session has been disabled"} />,
            document.getElementById('modal')
          );
        });
      }
    }
    
    render () {
      var rows = [];
      var self = this;
      this.state.sessionList.forEach(function (session, index) {
        rows.push(<UserSessionRow session={session} key={index} openModal={self.openConfirmModal}/>);
      });
      return (
        <div>
          <h3>Sessions&nbsp;</h3>
          <TokenNavigation updateNavigation={this.refreshSessionList} />
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Originiated IP Source</th>
                <th>Issued at</th>
                <th>Last seen</th>
                <th>Expires at</th>
                <th>Enabled</th>
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
  }
  
  function UserTokenRow (props) {
    return (
      <tr className={!props.token.enabled?"danger":""}>
        <td>{props.token.ip_source}</td>
        <td>{props.token.authorization_type}</td>
        <td>{(new Date(props.token.issued_at*1000)).toLocaleString()}</td>
        <td>{(new Date(props.token.last_seen*1000)).toLocaleString()}</td>
        <td>{(new Date(props.token.expired_at*1000)).toLocaleString()}</td>
        <td>{String(props.token.enabled)}</td>
        <td>
        {props.token.enabled?<Button className="btn btn-default" onClick={(event) => props.openModal(props.token, event)} data-toggle="tooltip" title="Revoke token">
            <i className="fa fa-trash"></i>
          </Button>:''}
        </td>
      </tr>
    );
  }
  
  class UserTokenTable extends React.Component {
    constructor(props) {
      super(props);
      this.state = {tokenList: this.props.tokenList};
      this.refreshTokenList = this.refreshTokenList.bind(this);
      this.openConfirmModal = this.openConfirmModal.bind(this);
      this.closeConfirmModal = this.closeConfirmModal.bind(this);
      
      this.state = {tokenList: this.props.tokenList, currentToken: {}}
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({tokenList: nextProps.tokenList});
    }
    
    refreshTokenList (valid, offset, limit) {
      var self = this;
      APIRequest("GET", "/profile/refresh_token/?valid=" + (valid?valid:"") + "&offset=" + (offset?offset:"") + "&limit=" + (limit?limit:""))
      .then(function (result) {
        self.setState({tokenList: result});
      });
    }
    
    openConfirmModal (token, evt) {
      this.setState({currentToken: token});
      ReactDOM.render(
        <ConfirmModal show={true} title={"Disable refresh token"} message={"Are you sure you want to disable this refresh token?"} onClose={this.closeConfirmModal} />,
        document.getElementById('modal')
      );
    }
    
    closeConfirmModal (result, evt) {
      var self = this;
      if (result) {
        APIRequest("DELETE", "/profile/refresh_token/", {token_hash: this.state.currentToken.token_hash})
        .then(function (result) {
          var currentToken = self.state.currentToken;
          currentToken.enabled = false;
          var tokenList = self.state.tokenList;
          tokenList.forEach(function (token) {
            if (token.token_hash === self.state.currentToken.token_hash) {
              token.enabled = false;
            }
          });
          self.setState({currentToken: currentToken, tokenList: tokenList});
          ReactDOM.render(
            <MessageModal show={true} title={"Refresh token disabled"} message={"The refresh token has been disabled"} />,
            document.getElementById('modal')
          );
        });
      }
    }
    
    render () {
      var rows = [];
      var self = this;
      this.state.tokenList.forEach(function (token, index) {
        rows.push(<UserTokenRow token={token} key={index} openModal={self.openConfirmModal}/>);
      });
      return (
        <div>
          <h3>Refresh tokens&nbsp;
            <small>
              <Button className="btn" onClick={this.refreshTokenList} data-toggle="tooltip" title="Refresh table">
                <i className="fa fa-refresh" aria-hidden="true"></i>
              </Button>
            </small>
          </h3>
          <TokenNavigation updateNavigation={this.refreshTokenList} />
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Originiated IP Source</th>
                <th>Authorization type</th>
                <th>Issued at</th>
                <th>Last seen</th>
                <th>Expires at</th>
                <th>Enabled</th>
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
  }
  
  class MessageModal extends React.Component {
    constructor(props) {
      super(props);

      this.state = {show: this.props.show, title: this.props.title, message: this.props.message};
      this.closeModal = this.closeModal.bind(this);
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({show: nextProps.show, title: nextProps.title, message: nextProps.message});
    }
    
    closeModal () {
      this.setState({show: false});
    }
    
    render () {
      return (
        <Modal show={this.state.show} onHide={this.closeModal}>
          <Modal.Header closeButton>
            <Modal.Title>{this.state.title}</Modal.Title>
          </Modal.Header>
          <Modal.Body>
          {this.state.message}
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={this.closeModal}>Close</Button>
          </Modal.Footer>
        </Modal>
      );
    }
  }

  class UpdateProfileButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleOpenModal = this.handleOpenModal.bind(this);
    }
    
    handleOpenModal() {
      ReactDOM.render(
        <ProfileEditModal show={true} closeModal={this.saveProfile} />,
        document.getElementById('modal')
      );
    }
    
    saveProfile (profile) {
      APIRequest("PUT", "/profile/", profile)
      .then(function (result) {
        profile = profile;
        ReactDOM.render(
          <UserDetails user={profile} />,
          document.getElementById('userDetails')
        );
        ReactDOM.render(
          <MessageModal show={true} title={"Profile"} message={"Profile updated"} />,
          document.getElementById('modal')
        );
      })
      .fail(function (error) {
        ReactDOM.render(
          <MessageModal show={true} title={"Profile"} message={"Error updating profile"} />,
          document.getElementById('modal')
        );
      });
    }
    
    render() {
      return (
        <Button className="btn btn-primary btn-block" onClick={(event) => this.handleOpenModal()} data-toggle="tooltip" title="Update my profile">
          <i className="fa fa-user" aria-hidden="true"></i>
          &nbsp;Update profile
        </Button>
      );
    }
  }

  class UpdatePasswordButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleOpenModal = this.handleOpenModal.bind(this);
    }
    
    handleOpenModal() {
      ReactDOM.render(
        <PasswordUpdateModal show={true} closeModal={this.saveProfile} />,
        document.getElementById('modal')
      );
    }
    
    saveProfile (profile) {
      APIRequest("PUT", "/profile/", profile)
      .then(function (result) {
        ReactDOM.render(
          <MessageModal show={true} title={"Password"} message={"Password updated"} />,
          document.getElementById('modal')
        );
      })
      .fail(function (error) {
        if (error.status === 400) {
          error.responseJSON.forEach(function (paramError) {
            for (var key in paramError) {
              if (key === "old_password" && paramError[key] === "old_password does not match") {
                ReactDOM.render(
                  <MessageModal show={true} title={"Current password"} message={"Current password is invalid"} />,
                  document.getElementById('modal')
                );
              }
            }
          });
        } else {
          ReactDOM.render(
            <MessageModal show={true} title={"Password"} message={"Error updating password"} />,
            document.getElementById('modal')
          );
        }
      });
    }
    
    render() {
      return (
        <Button className="btn btn-primary btn-block" onClick={(event) => this.handleOpenModal()} data-toggle="tooltip" title="Update my password">
          <i className="fa fa-key" aria-hidden="true"></i>
          &nbsp;Update password
        </Button>
      );
    }
  }

  class LogoutButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleLogout = this.handleLogout.bind(this);
    }
    
    render() {
      return (<Button className="btn btn-primary btn-block" onClick={this.handleLogout} data-toggle="tooltip" title="Log out">
        <i className="fa fa-sign-out" aria-hidden="true"></i>
        &nbsp;Log out
      </Button>);
    }
    
    handleLogout() {
      APIRequest("DELETE", "/auth/user/")
      .then(function (){
        if (document.search) {
          document.location = "login.html?" + document.search;
        } else {
          document.location = "login.html";
        }
      })
      .fail(function (error) {
        ReactDOM.render(
          <MessageModal show={true} title={"Disconnect session"} message={"Error while disconnecting this session"} />,
          document.getElementById('modal')
        );
      });
    }
  }

  class ContinueButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleContinue = this.handleContinue.bind(this);
    }
    
    render() {
      return (<Button type="button" className="btn btn-primary btn-block" onClick={this.handleContinue} data-toggle="tooltip" title="Continue to application">
        Continue to application
      </Button>);
    }
    
    handleContinue() {
      var redirect = "../glewlwyd/auth" + location.search + "&login_validated=true";
      window.location = redirect;
    }
  }

  class AdminButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleAdmin = this.handleAdmin.bind(this);
    }
    
    render() {
      return (<Button className="btn btn-primary btn-block" onClick={this.handleAdmin} data-toggle="tooltip" title="Glewlwyd administration">
        <i className="fa fa-users" aria-hidden="true"></i>
        &nbsp;Manage Glewlwyd
      </Button>);
    }
    
    handleAdmin() {
      window.location = "index.html";
    }
  }

  class LoginButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleLogin = this.handleLogin.bind(this);
    }
    
    render() {
      return (<Button type="button" className="btn btn-primary" onClick={this.handleLogin} data-toggle="tooltip" title="Log in">
        <i className="fa fa-sign-in" aria-hidden="true"></i>
        &nbsp;Log in
      </Button>);
    }
    
    handleLogin() {
      if (document.search) {
        document.location = "login.html?" + document.search;
      } else {
        document.location = "login.html";
      }
    }
  }

  function LoginComponent (props) {
    if (props.loggedIn) {
      var continueButton = "";
      var adminButton = "";
      if (location.search) {
        continueButton = <div className="row"><ContinueButton /></div>;
      }
      if (props.user.scope.indexOf("g_admin") > -1) {
        adminButton = <div className="row"><AdminButton /></div>;
      }
      return (
        <div>
          {continueButton}
          {adminButton}
          <div className="row">
            <UpdateProfileButton />
          </div>
          <div className="row">
            <UpdatePasswordButton />
          </div>
          <div className="row">
            <LogoutButton />
          </div>
        </div>
      );
    } else {
      return (
        <div>
          <LoginButton />
        </div>
      );
    }
  }
  
  function userDetails (user) {
    profile = user;
    ReactDOM.render(
      <UserDetails user={user} />,
      document.getElementById('userDetails')
    );
    APIRequest("GET", "/profile/session/")
    .then(function (result) {
      ReactDOM.render(
        <UserSessionTable sessionList={result} login={user.login}/>,
        document.getElementById('userSessionTable')
      );
    });
    APIRequest("GET", "/profile/refresh_token/")
    .then(function (result) {
      ReactDOM.render(
        <UserTokenTable tokenList={result} login={user.login}/>,
        document.getElementById('userTokenTable')
      );
    });
    $('.nav-tabs a[href="#userDetail"]').tab('show');
  }
  
  class ProfileEditModal extends React.Component {
    constructor(props) {
      super(props);
      this.state = {show: props.show, profile: profile, closeModal: this.props.closeModal, nameInvalid: false};
      
      this.handleChangeName = this.handleChangeName.bind(this);
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({show: nextProps.show, profile: profile, closeModal: nextProps.closeModal, nameInvalid: false});
    }
    
    closeModal (result) {
      if (result) {
        this.state.closeModal(this.state.profile);
      }
      this.setState({show: false});
    }
    
    handleChangeName (event) {
      var isInvalid = !event.target.value;
      var newProfile = $.extend({}, this.state.profile);
      newProfile.name = event.target.value || "";
      this.setState({profile: newProfile, nameInvalid: isInvalid});
    }
    
    handleChangeDescription (event) {
      var newProfile = $.extend({}, this.state.profile);
      newProfile.description = event.target.value || "";
      this.setState({profile: newProfile});
    }
    
    render () {
      return (
        <Modal show={this.state.show} onHide={() => this.closeModal(false)}>
          <Modal.Header closeButton>
            <Modal.Title>Profile</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="profileName">Update profile name</label>
              </div>
              <div className={this.state.nameInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="text" 
                       name="profileName" 
                       id="profileName" 
                       placeholder="Name" 
                       value={this.state.profile.name} 
                       onChange={this.handleChangeName}
                       data-toggle="tooltip" 
                       title="Your new name"></input>
              </div>
            </div>
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={() => this.closeModal(true)} disabled={this.state.nameInvalid}>Save</Button>
            <Button onClick={() => this.closeModal(false)}>Cancel</Button>
          </Modal.Footer>
        </Modal>
      );
    }
  }
  
  class PasswordUpdateModal extends React.Component {
    constructor(props) {
      super(props);
      this.state = {show: props.show, profile: {old_password: "", new_password: ""}, confirmPassword: "", closeModal: this.props.closeModal, curPasswordInvalid: true, newPasswordInvalid: true, newPasswordConfirmInvalid: true};
      
      this.handleChangeCurPassword = this.handleChangeCurPassword.bind(this);
      this.handleChangeNewPassword = this.handleChangeNewPassword.bind(this);
      this.handleChangeConfirmNewPassword = this.handleChangeConfirmNewPassword.bind(this);
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({show: nextProps.show, profile: {old_password: "", new_password: ""}, confirmPassword: "", closeModal: nextProps.closeModal, curPasswordInvalid: true, newPasswordInvalid: true, newPasswordConfirmInvalid: true});
    }
    
    closeModal (result) {
      if (result) {
        this.state.closeModal(this.state.profile);
      }
      this.setState({show: false});
    }
    
    handleChangeCurPassword (event) {
      var isInvalid = !event.target.value;
      var newProfile = $.extend({}, this.state.profile);
      newProfile.old_password = event.target.value || "";
      this.setState({profile: newProfile, curPasswordInvalid: isInvalid});
    }
    
    handleChangeNewPassword (event) {
      var isInvalid = !event.target.value || event.target.value.length < 8;
      var newProfile = $.extend({}, this.state.profile);
      newProfile.new_password = event.target.value || "";
      this.setState({profile: newProfile, newPasswordInvalid: isInvalid});
    }
    
    handleChangeConfirmNewPassword (event) {
      var isInvalid = !event.target.value || event.target.value.length < 8 || event.target.value != this.state.profile.new_password;
      this.setState({confirmPassword: event.target.value, newPasswordConfirmInvalid: isInvalid});
    }
    
    render () {
      return (
        <Modal show={this.state.show} onHide={() => this.closeModal(false)}>
          <Modal.Header closeButton>
            <Modal.Title>Update password</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="oldPassword">Current password</label>
              </div>
              <div className={this.state.curPasswordInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="password" 
                       name="oldPassword" 
                       id="oldPassword" 
                       placeholder="current password" 
                       value={this.state.profile.old_password} 
                       onChange={this.handleChangeCurPassword}
                       data-toggle="tooltip" 
                       title="Enter your current password"></input>
              </div>
            </div>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="newPassword">New password</label>
              </div>
              <div className={this.state.newPasswordInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="password" 
                       name="newPassword" 
                       id="newPassword" 
                       placeholder="new password" 
                       value={this.state.profile.new_password} 
                       onChange={this.handleChangeNewPassword}
                       data-toggle="tooltip" 
                       title="New password must be at least 8 characters"></input>
              </div>
            </div>
            <div className="row">
              <div className="col-md-6">
                <label htmlFor="confirmNewPassword">Confirm new password</label>
              </div>
              <div className={this.state.newPasswordConfirmInvalid?"col-md-6 has-error":"col-md-6"}>
                <input className="form-control" 
                       type="password" 
                       name="confirmNewPassword" 
                       id="confirmNewPassword" 
                       placeholder="confirm new password" 
                       value={this.state.confirmPassword} 
                       onChange={this.handleChangeConfirmNewPassword}
                       data-toggle="tooltip" 
                       title="Must exactly match new password"></input>
              </div>
            </div>
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={() => this.closeModal(true)} disabled={this.state.newPasswordConfirmInvalid||this.state.newPasswordConfirmInvalid||this.state.curPasswordInvalid}>Save</Button>
            <Button onClick={() => this.closeModal(false)}>Cancel</Button>
          </Modal.Footer>
        </Modal>
      );
    }
  }
  
  class ConfirmModal extends React.Component {
    constructor(props) {
      super(props);

      this.state = {show: this.props.show, title: this.props.title, message: this.props.message, onClose: this.props.onClose};
      this.closeModal = this.closeModal.bind(this);
    }
    
    componentWillReceiveProps(nextProps) {
      this.setState({show: nextProps.show, title: nextProps.title, message: nextProps.message, onClose: nextProps.onClose});
    }
    
    closeModal (result) {
      this.setState({show: false});
      this.state.onClose(result);
    }
    
    render () {
      return (
        <Modal show={this.state.show} onHide={() => this.closeModal(false)}>
          <Modal.Header closeButton>
            <Modal.Title>{this.state.title}</Modal.Title>
          </Modal.Header>
          <Modal.Body>
          {this.state.message}
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={() => this.closeModal(true)}>OK</Button>
            <Button onClick={() => this.closeModal(false)}>Cancel</Button>
          </Modal.Footer>
        </Modal>
      );
    }
  }
  
  class TokenNavigation extends React.Component {
    constructor(props) {
      super(props);
      
      this.state = {valid: "", limit: 10, offset: 0, updateNavigation: props.updateNavigation};

      this.handleChangeValid = this.handleChangeValid.bind(this);
      this.handlePreviousPage = this.handlePreviousPage.bind(this);
      this.handleChangeLimit = this.handleChangeLimit.bind(this);
      this.handleNextPage = this.handleNextPage.bind(this);
      this.handleRefresh = this.handleRefresh.bind(this);
    }

    handleChangeValid (event) {
      this.setState({valid: event.target.value});
      this.state.updateNavigation(event.target.value, this.state.offset, this.state.limit);
    }
    
    handleChangeLimit (event) {
      var limit = parseInt(event.target.value);
      this.setState({limit: limit});
      this.state.updateNavigation(this.state.valid, this.state.offset, limit);
    }
    
    handlePreviousPage (event) {
      var offset = this.state.offset-this.state.limit;
      this.setState({offset: offset});
      this.state.updateNavigation(this.state.valid, offset, this.state.limit);
    }
    
    handleNextPage (event) {
      var offset = this.state.offset+this.state.limit;
      this.setState({offset: offset});
      this.state.updateNavigation(this.state.valid, offset, this.state.limit);
    }
    
    handleRefresh (event) {
      event.preventDefault();
      this.state.updateNavigation(this.state.valid, this.state.offset, this.state.limit);
    }
    
    render () {
      return (
        <div className="col-md-12 container">
          <div className="row">
            <div className="col-md-12 input-group">
              <span className="input-group-btn">
                <Button className="btn btn-default" 
                        disabled={(this.state.offset===0)} 
                        type="button" 
                        onClick={this.handlePreviousPage}
                        data-toggle="tooltip" 
                        title="Previous page">
                  <i className="icon-resize-small fa fa-chevron-left"></i>
                </Button>
              </span>
              <select className="form-control input-small" onChange={this.handleChangeLimit} value={this.state.limit} data-toggle="tooltip" title="Page size">
                <option value="10">10</option>
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
              </select>
              <span className="input-group-btn paddingRight">
                <Button className="btn btn-default" type="button" onClick={this.handleNextPage} data-toggle="tooltip" title="Next page">
                  <i className="icon-resize-small fa fa-chevron-right"></i>
                </Button>
              </span>
              <select className="form-control input-small" onChange={this.handleChangeValid} value={this.state.valid} data-toggle="tooltip" title="Status">
                <option value="">Enabled and disabled</option>
                <option value="true">Enabled only</option>
                <option value="false">Disabled only</option>
              </select>
              <span className="input-group-btn paddingLeft">
                <Button className="btn btn-default" onClick={this.handleRefresh} data-toggle="tooltip" title="Refresh table">
                  <i className="icon-resize-small fa fa-refresh"></i>
                </Button>
              </span>
            </div>
          </div>
          <div className="row">
            <div className="col-md-12 text-right">
              <span className="text-center">{this.state.limit} results maximum, starting at result: {this.state.offset}</span>
            </div>
          </div>
        </div>
      );
    }
  }
  /**
   * Get server parameters
   * And initialize application
   */
  $.ajax({
    method: "GET",
    url: oauth.glewlwyd_server_url + "/config"
  })
  .done(function (result) {
    oauth.api_prefix = result.api_prefix;
    APIRequest("GET", "/profile/")
    .then(function (result) {
      userDetails(result);
      ReactDOM.render(
        <LoginComponent loggedIn={true} user={result} />,
        document.getElementById('profileActions')
      );
      APIRequest("GET", "/profile/")
      .then(function (result) {
        userDetails(result);
        ReactDOM.render(
          <LoginComponent loggedIn={true} user={result} />,
          document.getElementById('profileActions')
        );
      })
      .fail(function () {
        ReactDOM.render(
          <LoginComponent loggedIn={false} user={result} />,
          document.getElementById('profileActions')
        );
      });
    })
    .fail(function () {
      ReactDOM.render(
        <LoginComponent loggedIn={false} user={result} />,
        document.getElementById('profileActions')
      );
    });
  });

});