import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

import Navbar from './Navbar';
import User from './User';
import PasswordModal from './PasswordModal';
import SchemePage from './SchemePage';
import Confirm from '../Modal/Confirm';

class App extends Component {
  constructor(props) {
    super(props);

    this.state = {
      lang: i18next.language,
      config: props.config,
      curNav: "profile",
      profileList: false,
      schemeList: [],
      loggedIn: false,
      confirmModal: {
        title: "",
        message: "",
        callback: false
      }
    };
    
    this.fetchProfile = this.fetchProfile.bind(this);
    this.closePasswordModal = this.closePasswordModal.bind(this);
    
    messageDispatcher.subscribe('App', (message) => {
      if (message.type === 'nav') {
        if (message.page === "password") {
          $("#passwordModal").modal({keyboard: false, show: true});
        } else if (message.page === "profile") {
          this.setState({curNav: "profile"});
        } else {
          this.setState({curNav: message.module, module: message.page});
        }
      } else if (message.type === 'loggedIn') {
        this.setState({loggedIn: message.message}, () => {
          if (!this.state.loggedIn) {
            this.setState({profileList: false, schemeList: []});
          } else {
            this.fetchProfile();
          }
        });
      } else if (message.type === 'lang') {
        this.setState({lang: i18next.language});
      } else if (message.type === 'confirm') {
        var confirmModal = this.state.confirmModal;
        confirmModal.title = message.title;
        confirmModal.message = message.message;
        confirmModal.callback = message.callback;
        this.setState({confirmModal: confirmModal}, () => {
          $("#confirmModal").modal({keyboard: false, show: true});
        });
      } else if (message.type === 'closeConfirm') {
        $("#confirmModal").modal("hide");
      }
    });
    
    if (this.state.config) {
      this.fetchProfile();
    }
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: props.config
    });
  }
  
  fetchProfile() {
    apiManager.glewlwydRequest("/profile")
    .then((res) => {
      if (!res[0] || res[0].scope.indexOf(this.state.config.profile_scope) < 0) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
      } else {
        this.setState({loggedIn: true, profileList: res}, () => {
          apiManager.glewlwydRequest("/profile/scheme")
          .then((res) => {
            this.setState({schemeList: res});
          })
          .fail(() => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          });
        });
      }
    })
    .fail((error) => {
      if (error.status === 401) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
    });
  }

  closePasswordModal(result, data) {
    $("#passwordModal").modal("hide");
  }
  
	render() {
    if (this.state.config) {
      return (
        <div aria-live="polite" aria-atomic="true" style={{position: "relative", minHeight: "200px"}}>
          <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px', marginBottom: 20 + 'px'}}>
            <div className="card-header">
              <Navbar active={this.state.curNav} config={this.state.config} loggedIn={this.state.loggedIn} schemeList={this.state.schemeList}/>
            </div>
            <div className="card-body">
              <div id="carouselBody" className="carousel slide" data-ride="carousel">
                <div className="carousel-inner">
                  <div className={"carousel-item" + (this.state.curNav==="profile"?" active":"")}>
                    <User config={this.state.config} profile={(this.state.profileList?this.state.profileList[0]:false)} pattern={this.state.config?this.state.config.pattern.user:false}/>
                  </div>
                  <div className={"carousel-item" + (this.state.curNav!=="profile"?" active":"")}>
                    <SchemePage config={this.state.config} module={this.state.curNav} name={this.state.module} profile={(this.state.profileList?this.state.profileList[0]:false)} />
                  </div>
                </div>
              </div>
            </div>
          </div>
          <Notification/>
          <PasswordModal config={this.state.config} callback={this.closePasswordModal}/>
          <Confirm title={this.state.confirmModal.title} message={this.state.confirmModal.message} callback={this.state.confirmModal.callback} />
        </div>
      );
    } else {
      return (
        <div aria-live="polite" aria-atomic="true" style={{position: "relative", minHeight: "200px"}}>
          <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px', marginBottom: 20 + 'px'}}>
            <div className="card-header">
              <h4>
                <span className="badge badge-danger">
                  {i18next.t("error-api-connect")}
                </span>
              </h4>
            </div>
          </div>
        </div>
      );
    }
	}
}

export default App;
