// slack.js


import { useState, useEffect } from 'react';
import {
    Box,
    Button,
    CircularProgress
} from '@mui/material';
import axios from 'axios';

export const HubspotIntegration = ({ user, org, integrationParams, setIntegrationParams }) => {
    const [isConnected, setIsConnected] = useState(false);
    const [isConnecting, setIsConnecting] = useState(false);

    // Function to open OAuth in a new window
    const handleConnectClick = async () => {
        try {
            setIsConnecting(true);
            const formData = new FormData();
            formData.append('user_id', user);
            formData.append('org_id', org);
            const response = await axios.post(`http://localhost:8000/integrations/hubspot/authorize`, formData);
            const authURL = response?.data;

            const newWindow = window.open(authURL, 'Hubspot Authorization', 'width=600, height=600');

            // Polling for the window to close
            const pollTimer = window.setInterval(() => {
                if (newWindow?.closed !== false) { 
                    window.clearInterval(pollTimer);
                    handleWindowClosed();
                }
            }, 200);
        } catch (e) {
            setIsConnecting(false);
            alert(e?.response?.data?.detail);
        }
    }

    // Function to handle logic when the OAuth window closes
    const handleWindowClosed = async () => {
        try {
            // fetch credentials using user_id and org_id
            const formDataCreds = new FormData();
            formDataCreds.append('user_id', user);
            formDataCreds.append('org_id', org);
    
            const credentialsResponse = await axios.post(`http://localhost:8000/integrations/hubspot/credentials`, formDataCreds);
            const credentials = credentialsResponse.data; 
    
            if (credentials) {
                // Set the credentials in the integrationParams
                setIntegrationParams(prev => ({ 
                    ...prev, 
                    credentials: credentials, 
                    type: 'Hubspot'  
                }));
            }
            setIsConnecting(false);
        } catch (e) {
            setIsConnecting(false);
            alert(e?.response?.data?.detail || 'Something went wrong');
        }
    }
    useEffect(() => {
        setIsConnected(integrationParams?.credentials ? true : false)
    }, [integrationParams?.credentials]);
    

    return (
        <>
        <Box sx={{mt: 2}}>
            Parameters
            <Box display='flex' alignItems='center' justifyContent='center' sx={{mt: 2}}>
                <Button 
                    variant='contained' 
                    onClick={isConnected ? () => {} :handleConnectClick}
                    color={isConnected ? 'success' : 'primary'}
                    disabled={isConnecting}
                    style={{
                        pointerEvents: isConnected ? 'none' : 'auto',
                        cursor: isConnected ? 'default' : 'pointer',
                        opacity: isConnected ? 1 : undefined
                    }}
                >
                    {isConnected ? 'Hubspot Connected' : isConnecting ? <CircularProgress size={20} /> : 'Connect to Hubspot'}
                </Button>
            </Box>
        </Box>
      </>
    );
}
